//! Transfer Hook — Execute handler.
//!
//! Called by Token-2022 on **every** transfer of a hooked mint.
//! Enforces all spending rules and updates the on-chain tracker.
//!
//! ## Accounts
//!
//! | # | Account          | Source              | Flags    |
//! |---|------------------|---------------------|----------|
//! | 0 | source           | transfer ix         |          |
//! | 1 | mint             | transfer ix         |          |
//! | 2 | destination      | transfer ix         |          |
//! | 3 | authority        | transfer ix         |          |
//! | 4 | extra_metas_pda  | resolved by runtime |          |
//! | 5 | policy_pda       | resolved via seeds  | readonly |
//! | 6 | tracker_pda      | resolved via seeds  | writable |
//!
//! Policy and tracker PDAs are keyed to `["seed", mint, token_owner]` where
//! `token_owner` is read from the source token account's data (bytes 32..64).
//! This allows delegation to work: the authority may be a delegate, but the
//! PDAs always resolve to the token owner's policy.
//!
//! `instruction_data` contains the transfer amount as LE u64 (appended by
//! Token-2022 after stripping the 8-byte Execute discriminator).

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::sysvars::clock::Clock;
use pinocchio::sysvars::Sysvar;

use crate::error::VeilError;
use crate::state::*;

pub fn execute(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // ── Parse amount ─────────────────────────────────────────────────────
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );

    // ── Read token owner from source token account ──────────────────────
    // SPL Token / Token-2022 account layout: owner pubkey at bytes 32..64.
    let source_data = accounts[0].try_borrow()?;
    if source_data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut token_owner = [0u8; 32];
    token_owner.copy_from_slice(&source_data[32..64]);
    drop(source_data);

    let mint_addr = *accounts[1].address();
    let authority_addr = *accounts[3].address();

    // ── Validate policy PDA (keyed to token owner, not authority) ───────
    if !accounts[5].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }

    let (expected_policy, _) = Address::find_program_address(
        &[POLICY_SEED, mint_addr.as_ref(), &token_owner],
        &crate::ID,
    );
    if accounts[5].address() != &expected_policy {
        return Err(ProgramError::InvalidSeeds);
    }

    let pol = accounts[5].try_borrow()?;
    if pol.len() < POLICY_SIZE {
        return Err(VeilError::InvalidPolicyData.into());
    }
    if &pol[policy::DISC..policy::DISC + 8] != POLICY_DISC {
        return Err(VeilError::PolicyNotFound.into());
    }

    // ── Authority check: owner or delegate? ──────────────────────────────
    let is_owner = authority_addr.as_ref() == &token_owner;

    let mut delegate_tx_cap: u64 = 0;
    let mut delegate_daily_cap: u64 = 0;
    let mut is_delegate = false;

    if !is_owner {
        let n = pol[policy::DELEGATIONS_LEN] as usize;
        for i in 0..n.min(MAX_DELEGATIONS) {
            let base = policy::DELEGATIONS + i * DELEGATION_SLOT_SIZE;
            if authority_addr.as_ref() == &pol[base..base + 32] {
                is_delegate = true;
                delegate_daily_cap = read_u64(&pol, base + delegation::DAILY_CAP);
                delegate_tx_cap = read_u64(&pol, base + delegation::TX_CAP);
                break;
            }
        }
        if !is_delegate {
            return Err(VeilError::DelegationUnauthorized.into());
        }
    }

    // ── Per-transaction cap (enforce both global and delegate sub-cap) ──
    let global_tx_cap = read_u64(&pol, policy::TX_CAP);
    let tx_cap = if is_delegate && delegate_tx_cap > 0 {
        if global_tx_cap > 0 { global_tx_cap.min(delegate_tx_cap) } else { delegate_tx_cap }
    } else {
        global_tx_cap
    };
    if tx_cap > 0 && amount > tx_cap {
        return Err(VeilError::AmountExceedsTxCap.into());
    }

    // ── Extract whitelist + remaining policy fields, then drop borrow ──
    let mode = pol[policy::MODE];
    let mut wl_root = [0u8; 32];
    wl_root.copy_from_slice(&pol[policy::WHITELIST_ROOT..policy::WHITELIST_ROOT + 32]);

    let global_daily_cap = read_u64(&pol, policy::DAILY_CAP);
    let daily_cap = if is_delegate && delegate_daily_cap > 0 {
        if global_daily_cap > 0 { global_daily_cap.min(delegate_daily_cap) } else { delegate_daily_cap }
    } else {
        global_daily_cap
    };
    let monthly_cap = read_u64(&pol, policy::MONTHLY_CAP);
    let velocity_max = read_u16(&pol, policy::VELOCITY_MAX);
    let velocity_window = read_u16(&pol, policy::VELOCITY_WINDOW) as i64;
    let time_start = pol[policy::TIME_START_H];
    let time_end = pol[policy::TIME_END_H];
    drop(pol);

    // ── Whitelist check (needs accounts[7] borrow, so must be after pol drop)
    if mode == 0 && wl_root.iter().any(|&b| b != 0) {
        if accounts.len() < 8 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let dest_addr = *accounts[2].address();

        // Derive expected approval PDA: ["approval", mint, token_owner, destination]
        let (expected_approval, _) = Address::find_program_address(
            &[APPROVAL_SEED, mint_addr.as_ref(), &token_owner, dest_addr.as_ref()],
            &crate::ID,
        );
        if accounts[7].address() != &expected_approval {
            return Err(VeilError::RecipientNotWhitelisted.into());
        }
        if !accounts[7].owned_by(&crate::ID) {
            return Err(VeilError::RecipientNotWhitelisted.into());
        }

        let appr = accounts[7].try_borrow()?;
        if appr.len() < APPROVAL_SIZE {
            return Err(VeilError::RecipientNotWhitelisted.into());
        }
        if &appr[approval::DISC..approval::DISC + 8] != APPROVAL_DISC {
            return Err(VeilError::RecipientNotWhitelisted.into());
        }
        // Reject if approval root doesn't match current policy root (handles rotation)
        if &appr[approval::ROOT..approval::ROOT + 32] != &wl_root {
            return Err(VeilError::RecipientNotWhitelisted.into());
        }
        drop(appr);
    }
    // mode 1 (blacklist): allow all — no on-chain blacklist entries stored yet
    // mode 2 (open): allow all

    // ── Validate tracker PDA (also keyed to token owner) ────────────────
    if !accounts[6].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }
    let (expected_tracker, _) = Address::find_program_address(
        &[TRACKER_SEED, mint_addr.as_ref(), &token_owner],
        &crate::ID,
    );
    if accounts[6].address() != &expected_tracker {
        return Err(ProgramError::InvalidSeeds);
    }

    let mut trk = accounts[6].try_borrow_mut()?;
    if trk.len() < TRACKER_SIZE {
        return Err(VeilError::InvalidSpendTracker.into());
    }
    if &trk[tracker::DISC..tracker::DISC + 8] != TRACKER_DISC {
        return Err(VeilError::InvalidSpendTracker.into());
    }

    // ── Clock ────────────────────────────────────────────────────────────
    let now = Clock::get()?.unix_timestamp;

    // ── Rolling window resets ────────────────────────────────────────────
    if now - read_i64(&trk, tracker::DAILY_RESET_TS) >= SECONDS_PER_DAY {
        write_u64(&mut trk, tracker::DAILY_SPENT, 0);
        write_i64(&mut trk, tracker::DAILY_RESET_TS, now);
    }
    if now - read_i64(&trk, tracker::MONTHLY_RESET_TS) >= SECONDS_PER_MONTH {
        write_u64(&mut trk, tracker::MONTHLY_SPENT, 0);
        write_i64(&mut trk, tracker::MONTHLY_RESET_TS, now);
    }

    // ── Daily cap ────────────────────────────────────────────────────────
    let daily_spent = read_u64(&trk, tracker::DAILY_SPENT);
    if daily_cap > 0 {
        let new_daily = daily_spent.checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if new_daily > daily_cap {
            return Err(VeilError::DailyCapExceeded.into());
        }
    }

    // ── Monthly cap ──────────────────────────────────────────────────────
    let monthly_spent = read_u64(&trk, tracker::MONTHLY_SPENT);
    if monthly_cap > 0 {
        let new_monthly = monthly_spent.checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if new_monthly > monthly_cap {
            return Err(VeilError::MonthlyCapExceeded.into());
        }
    }

    // ── Velocity limit ───────────────────────────────────────────────────
    if velocity_max > 0 {
        let window_start = read_i64(&trk, tracker::VELOCITY_WINDOW_START);
        if now - window_start >= velocity_window {
            write_u16(&mut trk, tracker::VELOCITY_COUNT, 1);
            write_i64(&mut trk, tracker::VELOCITY_WINDOW_START, now);
        } else {
            let count = read_u16(&trk, tracker::VELOCITY_COUNT);
            if count >= velocity_max {
                return Err(VeilError::VelocityLimitExceeded.into());
            }
            write_u16(&mut trk, tracker::VELOCITY_COUNT, count + 1);
        }
    }

    // ── Time-of-day restriction ──────────────────────────────────────────
    if time_start != 0 || time_end != 0 {
        let hour = ((now % 86400) / 3600) as u8;
        let blocked = if time_start <= time_end {
            hour < time_start || hour >= time_end   // normal range
        } else {
            hour >= time_end && hour < time_start   // wraparound
        };
        if blocked {
            return Err(VeilError::TimeWindowViolation.into());
        }
    }

    // ── All checks passed — commit tracker updates ───────────────────────
    write_u64(&mut trk, tracker::DAILY_SPENT, daily_spent.saturating_add(amount));
    write_u64(&mut trk, tracker::MONTHLY_SPENT, monthly_spent.saturating_add(amount));

    let total = read_u64(&trk, tracker::TX_COUNT_TOTAL);
    write_u64(&mut trk, tracker::TX_COUNT_TOTAL, total.wrapping_add(1));

    Ok(())
}
