#![no_std]

//! # Veil — Programmable Money on Solana
//!
//! A Token-2022 **transfer hook** that enforces spending policies at the
//! *token* level.  Rules follow the money — not the wallet.
//!
//! Built from scratch in [Pinocchio](https://github.com/anza-xyz/pinocchio)
//! for minimal compute-unit cost: zero-copy state, no Anchor, no alloc in
//! the hot path.
//!
//! ## Architecture
//!
//! ```text
//!  Token-2022 transfer
//!        │
//!        ▼
//!  ┌─────────────┐    resolves     ┌──────────────────────┐
//!  │ ExtraAccount │───────────────▶│  Policy PDA (ro)     │
//!  │  MetaList    │                │  Tracker PDA (rw)    │
//!  └──────┬──────┘                └──────────────────────┘
//!         │                                 │
//!         ▼                                 ▼
//!  ┌─────────────┐    enforces     ┌──────────────────────┐
//!  │   Execute    │───────────────▶│  tx cap              │
//!  │   handler    │                │  daily / monthly cap │
//!  │              │                │  velocity limit      │
//!  │              │                │  time-of-day window  │
//!  │              │                │  whitelist / open    │
//!  │              │                │  delegation sub-caps │
//!  └─────────────┘                └──────────────────────┘
//! ```
//!
//! ## Instructions
//!
//! | Disc | Name                      | Description                                     |
//! |------|---------------------------|-------------------------------------------------|
//! | 0x00 | `CreatePolicy`            | Set up spending rules for a (mint, owner) pair  |
//! | 0x01 | `UpdatePolicy`            | Modify existing rules (owner only)              |
//! | 0x02 | `AddDelegation`           | Grant scoped spending to another wallet / agent |
//!
//! The two **Transfer Hook Interface** endpoints (`Execute` and
//! `InitializeExtraAccountMetas`) use the standard 8-byte SPL
//! discriminators and are routed automatically.

extern crate alloc;

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio_transfer_hook_interface::{
    EXECUTE_DISCRIMINATOR, INITIALIZE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR,
};

// Program ID — matches target/deploy/veil_hook-keypair.json
solana_address::declare_id!("J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1");

pinocchio::nostd_panic_handler!();

pub mod error;
pub mod state;
pub mod execute;
pub mod init_extra;
pub mod create_policy;
pub mod whitelist;

/// Our custom instruction discriminators (1-byte).
const CREATE_POLICY: u8 = 0x00;
const UPDATE_POLICY: u8 = 0x01;
const ADD_DELEGATION: u8 = 0x02;
const SET_WHITELIST_ROOT: u8 = 0x03;
const APPROVE_DESTINATION: u8 = 0x04;
const REVOKE_APPROVAL: u8 = 0x05;

// ── Entrypoint ───────────────────────────────────────────────────────────────

pinocchio::entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // Hook interface uses 8-byte discriminators; our custom ixs use 1-byte.
    // Check 8-byte first (hook calls are the hot path), then fall back.
    if instruction_data.len() >= 8 {
        let disc8: [u8; 8] = instruction_data[0..8]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        match disc8 {
            EXECUTE_DISCRIMINATOR => {
                return execute::execute(accounts, &instruction_data[8..]);
            }
            INITIALIZE_EXTRA_ACCOUNT_META_LIST_DISCRIMINATOR => {
                return init_extra::init_extra_account_metas(accounts, &instruction_data[8..]);
            }
            _ => {} // Fall through to 1-byte check.
        }
    }

    let (disc, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *disc {
        CREATE_POLICY => create_policy::create_policy(accounts, data),
        UPDATE_POLICY => create_policy::update_policy(accounts, data),
        ADD_DELEGATION => create_policy::add_delegation(accounts, data),
        SET_WHITELIST_ROOT => whitelist::set_whitelist_root(accounts, data),
        APPROVE_DESTINATION => whitelist::approve_destination(accounts, data),
        REVOKE_APPROVAL => whitelist::revoke_approval(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
