//! Whitelist management — set root, approve/revoke destinations.
//!
//! ## SetWhitelistRoot (disc 0x03)
//!
//! | # | Account    | Flags    |
//! |---|------------|----------|
//! | 0 | owner      | signer   |
//! | 1 | policy_pda | writable |
//!
//! Data: 32 bytes — SHA256 Merkle root (all zeros to clear).
//!
//! ## ApproveDestination (disc 0x04)
//!
//! | # | Account        | Flags                                             |
//! |---|----------------|---------------------------------------------------|
//! | 0 | owner          | signer, payer                                     |
//! | 1 | mint           |                                                   |
//! | 2 | policy_pda     |                                                   |
//! | 3 | destination    |                                                   |
//! | 4 | approval_pda   | writable, PDA `["approval", mint, owner, dest]`   |
//! | 5 | system_program |                                                   |
//!
//! Data: `[proof_len: u8] + [proof_len × 33 bytes: (position: u8, sibling: [u8;32])]`
//!
//! ## RevokeApproval (disc 0x05)
//!
//! | # | Account      | Flags    |
//! |---|--------------|----------|
//! | 0 | owner        | signer   |
//! | 1 | mint         |          |
//! | 2 | destination  |          |
//! | 3 | approval_pda | writable |

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio::error::ProgramError;
use pinocchio::cpi::{Seed, Signer};
use pinocchio::sysvars::rent::Rent;
use pinocchio::sysvars::Sysvar;
use pinocchio_system::instructions::CreateAccount;
use pinocchio_log::log;

use crate::error::VeilError;
use crate::state::*;

// ── SHA256 via sol_sha256 syscall ──────────────────────────────────────────

#[repr(C)]
struct SolBytes {
    addr: *const u8,
    len: u64,
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let val = SolBytes {
        addr: data.as_ptr(),
        len: data.len() as u64,
    };
    unsafe {
        pinocchio::syscalls::sol_sha256(
            &val as *const SolBytes as *const u8,
            1,
            result.as_mut_ptr(),
        );
    }
    result
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn sha256(_data: &[u8]) -> [u8; 32] {
    unimplemented!("sha256 only available in SBF — tests must go through mollusk-svm")
}

// ── SetWhitelistRoot ───────────────────────────────────────────────────────

pub fn set_whitelist_root(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < 32 {
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

    if pol.len() < POLICY_SIZE {
        return Err(VeilError::InvalidPolicyData.into());
    }
    if &pol[policy::DISC..policy::DISC + 8] != POLICY_DISC {
        return Err(VeilError::PolicyNotFound.into());
    }
    if owner_addr.as_ref() != &pol[policy::OWNER..policy::OWNER + 32] {
        return Err(VeilError::NotPolicyOwner.into());
    }

    pol[policy::WHITELIST_ROOT..policy::WHITELIST_ROOT + 32].copy_from_slice(&data[0..32]);

    log!("veil: whitelist root updated");
    Ok(())
}

// ── ApproveDestination ─────────────────────────────────────────────────────

pub fn approve_destination(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let proof_len = data[0] as usize;
    if proof_len > MAX_PROOF_DEPTH {
        return Err(ProgramError::InvalidInstructionData);
    }
    let expected_data_len = 1 + proof_len * 33;
    if data.len() < expected_data_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let owner_addr = *accounts[0].address();
    let mint_addr = *accounts[1].address();
    let destination_addr = *accounts[3].address();

    // ── Validate policy ────────────────────────────────────────────────
    if !accounts[2].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }
    let pol = accounts[2].try_borrow()?;
    if pol.len() < POLICY_SIZE {
        return Err(VeilError::InvalidPolicyData.into());
    }
    if &pol[policy::DISC..policy::DISC + 8] != POLICY_DISC {
        return Err(VeilError::PolicyNotFound.into());
    }
    if owner_addr.as_ref() != &pol[policy::OWNER..policy::OWNER + 32] {
        return Err(VeilError::NotPolicyOwner.into());
    }
    if mint_addr.as_ref() != &pol[policy::MINT..policy::MINT + 32] {
        return Err(ProgramError::InvalidSeeds);
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&pol[policy::WHITELIST_ROOT..policy::WHITELIST_ROOT + 32]);
    drop(pol);

    // Root must be non-zero (whitelist must be configured)
    if root.iter().all(|&b| b == 0) {
        return Err(ProgramError::InvalidInstructionData);
    }

    // ── Verify Merkle proof ────────────────────────────────────────────
    // Leaf = SHA256(destination_address)
    let mut computed = sha256(destination_addr.as_ref());

    for i in 0..proof_len {
        let base = 1 + i * 33;
        let position = data[base];
        if position > 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let sibling = &data[base + 1..base + 33];

        let mut combined = [0u8; 64];
        if position == 0 {
            // current is left, sibling is right
            combined[0..32].copy_from_slice(&computed);
            combined[32..64].copy_from_slice(sibling);
        } else {
            // sibling is left, current is right
            combined[0..32].copy_from_slice(sibling);
            combined[32..64].copy_from_slice(&computed);
        }
        computed = sha256(&combined);
    }

    if computed != root {
        return Err(VeilError::InvalidMerkleProof.into());
    }

    // ── Derive + validate approval PDA ─────────────────────────────────
    let (expected_approval, bump) = Address::find_program_address(
        &[APPROVAL_SEED, mint_addr.as_ref(), owner_addr.as_ref(), destination_addr.as_ref()],
        &crate::ID,
    );
    if accounts[4].address() != &expected_approval {
        return Err(ProgramError::InvalidSeeds);
    }

    // ── Create or update approval PDA ──────────────────────────────────
    if accounts[4].is_data_empty() {
        let rent = Rent::get()?;
        let lamports = rent.try_minimum_balance(APPROVAL_SIZE)?;

        let bump_ref = [bump];
        let signer_seeds = [
            Seed::from(APPROVAL_SEED),
            Seed::from(mint_addr.as_ref()),
            Seed::from(owner_addr.as_ref()),
            Seed::from(destination_addr.as_ref()),
            Seed::from(&bump_ref),
        ];
        let signer = Signer::from(&signer_seeds);

        CreateAccount {
            from: &accounts[0],
            to: &accounts[4],
            lamports,
            space: APPROVAL_SIZE as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[signer])?;

        let mut appr = accounts[4].try_borrow_mut()?;
        appr[approval::DISC..approval::DISC + 8].copy_from_slice(APPROVAL_DISC);
        appr[approval::ROOT..approval::ROOT + 32].copy_from_slice(&root);
        appr[approval::DESTINATION..approval::DESTINATION + 32]
            .copy_from_slice(destination_addr.as_ref());
    } else {
        // Re-approval (e.g. after root rotation) — update root only
        if !accounts[4].owned_by(&crate::ID) {
            return Err(VeilError::InvalidOwner.into());
        }
        let mut appr = accounts[4].try_borrow_mut()?;
        if appr.len() < APPROVAL_SIZE {
            return Err(VeilError::InvalidPolicyData.into());
        }
        if &appr[approval::DISC..approval::DISC + 8] != APPROVAL_DISC {
            return Err(VeilError::InvalidPolicyData.into());
        }
        appr[approval::ROOT..approval::ROOT + 32].copy_from_slice(&root);
    }

    log!("veil: destination approved");
    Ok(())
}

// ── RevokeApproval ─────────────────────────────────────────────────────────

pub fn revoke_approval(accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !accounts[0].is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let owner_addr = *accounts[0].address();
    let mint_addr = *accounts[1].address();
    let destination_addr = *accounts[2].address();

    // ── Validate approval PDA ──────────────────────────────────────────
    let (expected_approval, _) = Address::find_program_address(
        &[APPROVAL_SEED, mint_addr.as_ref(), owner_addr.as_ref(), destination_addr.as_ref()],
        &crate::ID,
    );
    if accounts[3].address() != &expected_approval {
        return Err(ProgramError::InvalidSeeds);
    }
    if !accounts[3].owned_by(&crate::ID) {
        return Err(VeilError::InvalidOwner.into());
    }

    {
        let appr = accounts[3].try_borrow()?;
        if appr.len() < APPROVAL_SIZE {
            return Err(VeilError::InvalidPolicyData.into());
        }
        if &appr[approval::DISC..approval::DISC + 8] != APPROVAL_DISC {
            return Err(VeilError::InvalidPolicyData.into());
        }
    }

    // ── Close the approval PDA ─────────────────────────────────────────
    // Transfer lamports to owner, zero data, assign to system program.
    let approval_lam = accounts[3].lamports();
    accounts[0].set_lamports(
        accounts[0].lamports().checked_add(approval_lam)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    accounts[3].set_lamports(0);

    {
        let mut data = accounts[3].try_borrow_mut()?;
        data.fill(0);
    }

    // Assign to system program (address = [0; 32])
    let system_program: Address = [0u8; 32].into();
    unsafe { accounts[3].assign(&system_program); }

    log!("veil: approval revoked");
    Ok(())
}
