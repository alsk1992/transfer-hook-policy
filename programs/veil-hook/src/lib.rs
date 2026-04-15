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

// Program ID — replace with actual deployed keypair.
solana_address::declare_id!("7ZY7yGRoP8v8DniL8YHVR5PcCZq33RCg1zM6nwj9ijRy");

pinocchio::nostd_panic_handler!();

pub mod error;
pub mod state;
pub mod execute;
pub mod init_extra;
pub mod create_policy;

// ── Discriminators ───────────────────────────────────────────────────────────

/// 8-byte hash of `spl-transfer-hook-interface:execute`.
pub const EXECUTE_DISC: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

/// 8-byte hash of `spl-transfer-hook-interface:initialize-extra-account-metas`.
const INIT_EXTRA_METAS_DISC: [u8; 8] = [43, 34, 13, 49, 167, 88, 235, 235];

/// Our custom instruction discriminators (1-byte).
const CREATE_POLICY: u8 = 0x00;
const UPDATE_POLICY: u8 = 0x01;
const ADD_DELEGATION: u8 = 0x02;

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
            EXECUTE_DISC => {
                return execute::execute(accounts, &instruction_data[8..]);
            }
            INIT_EXTRA_METAS_DISC => {
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
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
