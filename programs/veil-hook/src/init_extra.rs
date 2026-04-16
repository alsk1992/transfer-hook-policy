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
use pinocchio::cpi::{Seed as CpiSeed, Signer};
use pinocchio_system::instructions::CreateAccount;
use pinocchio::sysvars::rent::Rent;
use pinocchio::sysvars::Sysvar;
use pinocchio_log::log;
use pinocchio_transfer_hook_interface::{
    EXECUTE_DISCRIMINATOR,
    state::{ExtraAccountMeta, ExtraAccountMetaList, Seed},
};

use crate::error::VeilError;
use crate::state::*;

/// Total bytes for the ExtraAccountMetaList PDA (3 entries).
pub const EXTRA_METAS_DATA_SIZE: usize = ExtraAccountMetaList::size_of(3);

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
        CpiSeed::from(EXTRA_METAS_SEED),
        CpiSeed::from(mint_addr.as_ref()),
        CpiSeed::from(&bump_ref),
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

    let metas = [
        // Entry 0: Policy PDA (read-only)
        // seeds = ["policy", mint(idx 1), source.owner(idx 0, offset 32, len 32)]
        ExtraAccountMeta::new_with_seeds(
            &[
                literal_seed(POLICY_SEED),
                Seed::AccountKey { index: 1 },
                Seed::AccountData { account_index: 0, data_index: 32, length: 32 },
            ],
            false,
            false,
        )?,
        // Entry 1: Tracker PDA (writable)
        // seeds = ["tracker", mint(idx 1), source.owner(idx 0, offset 32, len 32)]
        ExtraAccountMeta::new_with_seeds(
            &[
                literal_seed(TRACKER_SEED),
                Seed::AccountKey { index: 1 },
                Seed::AccountData { account_index: 0, data_index: 32, length: 32 },
            ],
            false,
            true,
        )?,
        // Entry 2: Approval PDA (read-only)
        // seeds = ["approval", mint(idx 1), source.owner(idx 0, offset 32, len 32), dest(idx 2)]
        ExtraAccountMeta::new_with_seeds(
            &[
                literal_seed(APPROVAL_SEED),
                Seed::AccountKey { index: 1 },
                Seed::AccountData { account_index: 0, data_index: 32, length: 32 },
                Seed::AccountKey { index: 2 },
            ],
            false,
            false,
        )?,
    ];

    ExtraAccountMetaList::init(&mut buf, &EXECUTE_DISCRIMINATOR, &metas)?;

    log!("veil: extra account metas initialized");
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create a [`Seed::Literal`] from a byte slice.
fn literal_seed(s: &[u8]) -> Seed {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s);
    Seed::Literal { bytes, length: s.len() as u8 }
}
