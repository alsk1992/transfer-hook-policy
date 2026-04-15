//! CreatePolicy / UpdatePolicy / AddDelegation instructions.
//!
//! ## CreatePolicy
//!
//! Initialize a new Policy PDA + SpendTracker PDA for a (mint, owner) pair.
//!
//! | # | Account        | Flags                                  |
//! |---|----------------|----------------------------------------|
//! | 0 | owner          | signer, payer                          |
//! | 1 | mint           |                                        |
//! | 2 | policy_pda     | writable, PDA `["policy", mint, owner]`|
//! | 3 | tracker_pda    | writable, PDA `["tracker",mint, owner]`|
//! | 4 | system_program |                                        |
//!
//! Instruction data (31 bytes after 1-byte discriminator):
//!
//! ```text
//!   [0..8]   tx_cap          u64
//!   [8..16]  daily_cap       u64
//!   [16..24] monthly_cap     u64
//!   [24..26] velocity_max    u16
//!   [26..28] velocity_window u16
//!   [28]     time_start_h    u8
//!   [29]     time_end_h      u8
//!   [30]     mode            u8  (0=whitelist, 1=blacklist, 2=open)
//! ```

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::cpi::{Seed, Signer};
use pinocchio::sysvars::rent::Rent;
use pinocchio::sysvars::clock::Clock;
use pinocchio::sysvars::Sysvar;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_log::log;

use crate::error::VeilError;
use crate::state::*;

pub const CREATE_POLICY_DATA_LEN: usize = 31;

// ── CreatePolicy ─────────────────────────────────────────────────────────────

pub fn create_policy(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < CREATE_POLICY_DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data[30] > 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let owner_addr = *accounts[0].address();
    let mint_addr = *accounts[1].address();

    // ── Derive + validate Policy PDA ─────────────────────────────────────
    let (expected_policy, policy_bump) = Address::find_program_address(
        &[POLICY_SEED, mint_addr.as_ref(), owner_addr.as_ref()],
        &crate::ID,
    );
    if accounts[2].address() != &expected_policy {
        return Err(ProgramError::InvalidSeeds);
    }
    if !accounts[2].is_data_empty() {
        return Err(VeilError::AlreadyInitialized.into());
    }

    // ── Derive + validate Tracker PDA ────────────────────────────────────
    let (expected_tracker, tracker_bump) = Address::find_program_address(
        &[TRACKER_SEED, mint_addr.as_ref(), owner_addr.as_ref()],
        &crate::ID,
    );
    if accounts[3].address() != &expected_tracker {
        return Err(ProgramError::InvalidSeeds);
    }

    let rent = Rent::get()?;

    // ── Create Policy PDA ────────────────────────────────────────────────
    {
        let lamports = rent.try_minimum_balance(POLICY_SIZE)?;
        let bump_ref = [policy_bump];
        let seeds = [
            Seed::from(POLICY_SEED),
            Seed::from(mint_addr.as_ref()),
            Seed::from(owner_addr.as_ref()),
            Seed::from(&bump_ref),
        ];
        CreateAccount {
            from: &accounts[0],
            to: &accounts[2],
            lamports,
            space: POLICY_SIZE as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    }

    // ── Write policy data ────────────────────────────────────────────────
    {
        let mut pol = accounts[2].try_borrow_mut()?;
        pol[policy::DISC..policy::DISC + 8].copy_from_slice(POLICY_DISC);
        pol[policy::OWNER..policy::OWNER + 32].copy_from_slice(owner_addr.as_ref());
        pol[policy::MINT..policy::MINT + 32].copy_from_slice(mint_addr.as_ref());

        pol[policy::TX_CAP..policy::TX_CAP + 8].copy_from_slice(&data[0..8]);
        pol[policy::DAILY_CAP..policy::DAILY_CAP + 8].copy_from_slice(&data[8..16]);
        pol[policy::MONTHLY_CAP..policy::MONTHLY_CAP + 8].copy_from_slice(&data[16..24]);
        pol[policy::VELOCITY_MAX..policy::VELOCITY_MAX + 2].copy_from_slice(&data[24..26]);
        pol[policy::VELOCITY_WINDOW..policy::VELOCITY_WINDOW + 2].copy_from_slice(&data[26..28]);
        pol[policy::TIME_START_H] = data[28];
        pol[policy::TIME_END_H] = data[29];
        pol[policy::MODE] = data[30];
    }

    // ── Create Tracker PDA ───────────────────────────────────────────────
    {
        let lamports = rent.try_minimum_balance(TRACKER_SIZE)?;
        let bump_ref = [tracker_bump];
        let seeds = [
            Seed::from(TRACKER_SEED),
            Seed::from(mint_addr.as_ref()),
            Seed::from(owner_addr.as_ref()),
            Seed::from(&bump_ref),
        ];
        CreateAccount {
            from: &accounts[0],
            to: &accounts[3],
            lamports,
            space: TRACKER_SIZE as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[Signer::from(&seeds)])?;
    }

    // ── Initialize tracker ───────────────────────────────────────────────
    {
        let now = Clock::get()?.unix_timestamp;
        let mut trk = accounts[3].try_borrow_mut()?;
        trk[tracker::DISC..tracker::DISC + 8].copy_from_slice(TRACKER_DISC);
        write_i64(&mut trk, tracker::DAILY_RESET_TS, now);
        write_i64(&mut trk, tracker::MONTHLY_RESET_TS, now);
        write_i64(&mut trk, tracker::VELOCITY_WINDOW_START, now);
    }

    log!("veil: policy created");
    Ok(())
}

// ── UpdatePolicy ─────────────────────────────────────────────────────────────

/// Modify an existing policy.  Owner-only.
///
/// | # | Account    | Flags    |
/// |---|------------|----------|
/// | 0 | owner      | signer   |
/// | 1 | policy_pda | writable |
pub fn update_policy(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < CREATE_POLICY_DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data[30] > 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !accounts[1].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }

    let owner_addr = *accounts[0].address();
    let mut pol = accounts[1].try_borrow_mut()?;

    if &pol[policy::DISC..policy::DISC + 8] != POLICY_DISC {
        return Err(VeilError::PolicyNotFound.into());
    }
    if owner_addr.as_ref() != &pol[policy::OWNER..policy::OWNER + 32] {
        return Err(VeilError::NotPolicyOwner.into());
    }

    pol[policy::TX_CAP..policy::TX_CAP + 8].copy_from_slice(&data[0..8]);
    pol[policy::DAILY_CAP..policy::DAILY_CAP + 8].copy_from_slice(&data[8..16]);
    pol[policy::MONTHLY_CAP..policy::MONTHLY_CAP + 8].copy_from_slice(&data[16..24]);
    pol[policy::VELOCITY_MAX..policy::VELOCITY_MAX + 2].copy_from_slice(&data[24..26]);
    pol[policy::VELOCITY_WINDOW..policy::VELOCITY_WINDOW + 2].copy_from_slice(&data[26..28]);
    pol[policy::TIME_START_H] = data[28];
    pol[policy::TIME_END_H] = data[29];
    pol[policy::MODE] = data[30];

    log!("veil: policy updated");
    Ok(())
}

// ── AddDelegation ────────────────────────────────────────────────────────────

/// Grant a delegate wallet scoped spending authority.
///
/// | # | Account    | Flags    |
/// |---|------------|----------|
/// | 0 | owner      | signer   |
/// | 1 | policy_pda | writable |
///
/// Instruction data (48 bytes):
/// ```text
///   [0..32]  delegate pubkey
///   [32..40] daily_cap  u64
///   [40..48] tx_cap     u64
/// ```
pub fn add_delegation(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < 48 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !accounts[1].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }

    let owner_addr = *accounts[0].address();
    let mut pol = accounts[1].try_borrow_mut()?;

    if &pol[policy::DISC..policy::DISC + 8] != POLICY_DISC {
        return Err(VeilError::PolicyNotFound.into());
    }
    if owner_addr.as_ref() != &pol[policy::OWNER..policy::OWNER + 32] {
        return Err(VeilError::NotPolicyOwner.into());
    }

    let n = pol[policy::DELEGATIONS_LEN] as usize;
    if n >= MAX_DELEGATIONS {
        return Err(ProgramError::AccountDataTooSmall);
    }

    let base = policy::DELEGATIONS + n * DELEGATION_SLOT_SIZE;
    pol[base..base + 32].copy_from_slice(&data[0..32]);
    pol[base + delegation::DAILY_CAP..base + delegation::DAILY_CAP + 8].copy_from_slice(&data[32..40]);
    pol[base + delegation::TX_CAP..base + delegation::TX_CAP + 8].copy_from_slice(&data[40..48]);
    pol[policy::DELEGATIONS_LEN] = (n + 1) as u8;

    log!("veil: delegation added");
    Ok(())
}
