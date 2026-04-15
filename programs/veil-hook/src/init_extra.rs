//! Initialize the ExtraAccountMetaList PDA for our transfer hook.
//!
//! Must be called once per mint before any hooked transfer can succeed.
//! Tells Token-2022 which additional PDAs the Execute handler requires:
//!
//!   1. **Policy PDA**  — seeds `["policy",  mint, source.owner]`, read-only
//!   2. **Tracker PDA** — seeds `["tracker", mint, source.owner]`, writable
//!
//! The third seed component reads the **token account owner** from the source
//! token account's data (bytes 32..64, standard SPL Token / Token-2022 layout).
//! This ensures the correct policy is resolved regardless of whether the
//! transfer authority is the owner or a delegate.
//!
//! ## Accounts
//!
//! | # | Account          | Flags             |
//! |---|------------------|-------------------|
//! | 0 | extra_metas_pda  | writable, PDA     |
//! | 1 | mint             |                   |
//! | 2 | authority        | signer (= payer)  |
//! | 3 | system_program   |                   |

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::cpi::{Seed, Signer};
use pinocchio_system::instructions::CreateAccount;
use pinocchio::sysvars::rent::Rent;
use pinocchio::sysvars::Sysvar;
use pinocchio_log::log;

use crate::error::VeilError;
use crate::state::*;

// ── TLV Layout ───────────────────────────────────────────────────────────────
//
// SPL ExtraAccountMetaList binary format:
//
// ```text
//   [0..8]    ArrayDiscriminator  (8 bytes — EXECUTE_DISC)
//   [8..12]   Length              (u32 LE  — byte size of the value)
//   [12..16]  count               (u32 LE  — number of entries)
//   [16..]    entries             (35 bytes each)
// ```
//
// Each ExtraAccountMeta entry (35 bytes):
//
// ```text
//   [0]       discriminator   0 = literal pubkey, 1 = PDA from executing program
//   [1..33]   address_config  32 bytes — raw pubkey or packed seed definitions
//   [33]      is_signer       0 | 1
//   [34]      is_writable     0 | 1
// ```
//
// Seed encoding inside address_config (for discriminator = 1):
//   type 0 = stop sentinel
//   type 1 = literal:          [1, len, ...bytes]
//   type 2 = instruction_data: [2, offset, len]
//   type 3 = account_key:      [3, account_index]
//   type 4 = account_data:     [4, account_index, data_offset, data_len]

/// Header (8 disc + 4 len + 4 count) + 2 entries × 35 bytes = 86.
pub const EXTRA_METAS_DATA_SIZE: usize = 86;

pub fn init_extra_account_metas(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let mint_addr = *accounts[1].address();

    if !accounts[2].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !accounts[0].is_data_empty() {
        return Err(VeilError::AlreadyInitialized.into());
    }

    // ── Derive + validate PDA ────────────────────────────────────────────
    let (expected_pda, bump) = Address::find_program_address(
        &[EXTRA_METAS_SEED, mint_addr.as_ref()],
        &crate::ID,
    );
    if accounts[0].address() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // ── Create the PDA account ───────────────────────────────────────────
    let rent = Rent::get()?;
    let lamports = rent.try_minimum_balance(EXTRA_METAS_DATA_SIZE)?;

    let bump_ref = [bump];
    let signer_seeds = [
        Seed::from(EXTRA_METAS_SEED),
        Seed::from(mint_addr.as_ref()),
        Seed::from(&bump_ref),
    ];
    let signer = Signer::from(&signer_seeds);

    CreateAccount {
        from: &accounts[2],
        to: &accounts[0],
        lamports,
        space: EXTRA_METAS_DATA_SIZE as u64,
        owner: &crate::ID,
    }
    .invoke_signed(&[signer])?;

    // ── Write ExtraAccountMetaList ───────────────────────────────────────
    let mut buf = accounts[0].try_borrow_mut()?;

    // TLV header
    buf[0..8].copy_from_slice(&crate::EXECUTE_DISC);                // 8-byte discriminator
    let value_len: u32 = 4 + 2 * 35;                               // count(4) + entries(70)
    buf[8..12].copy_from_slice(&value_len.to_le_bytes());           // length
    buf[12..16].copy_from_slice(&2u32.to_le_bytes());               // count = 2

    // Entry 0: Policy PDA (read-only)
    // seeds = [b"policy", mint_key(idx 1), source_token_account.owner(idx 0, offset 32, len 32)]
    write_extra_meta(
        &mut buf[16..16 + 35],
        false,
        false,
        &[
            SeedDef::Literal(POLICY_SEED),
            SeedDef::AccountKey(1),
            SeedDef::AccountData(0, 32, 32),
        ],
    );

    // Entry 1: Tracker PDA (writable)
    // seeds = [b"tracker", mint_key(idx 1), source_token_account.owner(idx 0, offset 32, len 32)]
    write_extra_meta(
        &mut buf[51..51 + 35],
        false,
        true,
        &[
            SeedDef::Literal(TRACKER_SEED),
            SeedDef::AccountKey(1),
            SeedDef::AccountData(0, 32, 32),
        ],
    );

    log!("veil: extra account metas initialized");
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

enum SeedDef<'a> {
    Literal(&'a [u8]),
    AccountKey(u8),
    AccountData(u8, u8, u8),
}

/// Pack one PDA-based ExtraAccountMeta into a 35-byte buffer.
///
/// Layout: `[disc=1][address_config × 32][is_signer][is_writable]`
fn write_extra_meta(buf: &mut [u8], is_signer: bool, is_writable: bool, seeds: &[SeedDef]) {
    buf[0] = 1; // discriminator: PDA from executing program

    // Pack seeds into address_config (bytes 1..33)
    let config = &mut buf[1..33];
    let mut off = 0;
    for seed in seeds {
        match seed {
            SeedDef::Literal(bytes) => {
                // type 1 = literal: [1, len, ...bytes]
                if off + 2 + bytes.len() > 32 { break; }
                config[off] = 1;
                config[off + 1] = bytes.len() as u8;
                config[off + 2..off + 2 + bytes.len()].copy_from_slice(bytes);
                off += 2 + bytes.len();
            }
            SeedDef::AccountKey(idx) => {
                // type 3 = account_key: [3, index]
                if off + 2 > 32 { break; }
                config[off] = 3;
                config[off + 1] = *idx;
                off += 2;
            }
            SeedDef::AccountData(account_idx, data_offset, data_len) => {
                // type 4 = account_data: [4, account_index, data_offset, data_len]
                if off + 4 > 32 { break; }
                config[off] = 4;
                config[off + 1] = *account_idx;
                config[off + 2] = *data_offset;
                config[off + 3] = *data_len;
                off += 4;
            }
        }
    }
    // Zero-fill remaining (type 0 = stop sentinel)
    config[off..].fill(0);

    buf[33] = is_signer as u8;
    buf[34] = is_writable as u8;
}
