//! Integration tests for the Veil transfer hook program.
//!
//! Uses mollusk-svm to run the compiled SBF binary in a minified SVM.

use mollusk_svm::{result::Check, Mollusk};
use sha2::{Sha256, Digest};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

// ── Constants matching the on-chain program ────────────────────────────────────

fn program_id() -> Pubkey {
    "J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1"
        .parse()
        .unwrap()
}

fn system_program_id() -> Pubkey {
    solana_sdk_ids::system_program::id()
}

fn system_program_account() -> Account {
    Account {
        lamports: 1,
        data: vec![],
        owner: solana_sdk_ids::native_loader::id(),
        executable: true,
        rent_epoch: 0,
    }
}

// Instruction discriminators
const EXECUTE_DISC: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
const INIT_EXTRA_METAS_DISC: [u8; 8] = [43, 34, 13, 49, 167, 88, 235, 235];
const CREATE_POLICY: u8 = 0x00;
const UPDATE_POLICY: u8 = 0x01;
const ADD_DELEGATION: u8 = 0x02;
const SET_WHITELIST_ROOT: u8 = 0x03;
const APPROVE_DESTINATION: u8 = 0x04;
const REVOKE_APPROVAL: u8 = 0x05;

// PDA seeds
const POLICY_SEED: &[u8] = b"policy";
const TRACKER_SEED: &[u8] = b"tracker";
const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";
const APPROVAL_SEED: &[u8] = b"approval";

// Account sizes
const POLICY_SIZE: usize = 240;
const TRACKER_SIZE: usize = 64;
const APPROVAL_SIZE: usize = 73;
const EXTRA_METAS_DATA_SIZE: usize = 121;

// State discriminators
const POLICY_DISC: &[u8; 8] = b"veilpol\0";
const TRACKER_DISC: &[u8; 8] = b"veiltrk\0";
const APPROVAL_DISC: &[u8; 8] = b"veilwl\0\0";

// Policy field offsets
mod pol {
    pub const DISC: usize = 0;
    pub const OWNER: usize = 8;
    pub const MINT: usize = 40;
    pub const TX_CAP: usize = 72;
    pub const DAILY_CAP: usize = 80;
    pub const MONTHLY_CAP: usize = 88;
    pub const VELOCITY_MAX: usize = 96;
    pub const VELOCITY_WINDOW: usize = 98;
    pub const TIME_START_H: usize = 100;
    pub const TIME_END_H: usize = 101;
    pub const MODE: usize = 102;
    pub const WHITELIST_ROOT: usize = 104;
    pub const DELEGATIONS_LEN: usize = 136;
    pub const DELEGATIONS: usize = 138;
}

// Tracker field offsets
mod trk {
    pub const DISC: usize = 0;
    pub const DAILY_SPENT: usize = 8;
    pub const MONTHLY_SPENT: usize = 16;
    pub const DAILY_RESET_TS: usize = 24;
    pub const MONTHLY_RESET_TS: usize = 32;
    pub const VELOCITY_COUNT: usize = 40;
    pub const VELOCITY_WINDOW_START: usize = 42;
    pub const TX_COUNT_TOTAL: usize = 50;
}

// Delegation offsets (relative to slot base)
mod deleg {
    pub const DAILY_CAP: usize = 32;
    pub const TX_CAP: usize = 40;
}

// Error codes
const ERR_RECIPIENT_NOT_WHITELISTED: u32 = 0x5600;
const ERR_AMOUNT_EXCEEDS_TX_CAP: u32 = 0x5601;
const ERR_DAILY_CAP_EXCEEDED: u32 = 0x5602;
const ERR_MONTHLY_CAP_EXCEEDED: u32 = 0x5603;
const ERR_VELOCITY_LIMIT_EXCEEDED: u32 = 0x5604;
const ERR_TIME_WINDOW_VIOLATION: u32 = 0x5605;
const ERR_DELEGATION_UNAUTHORIZED: u32 = 0x5606;
const ERR_NOT_POLICY_OWNER: u32 = 0x560B;
const ERR_ALREADY_INITIALIZED: u32 = 0x560D;
const ERR_INVALID_MERKLE_PROOF: u32 = 0x560E;

// Approval field offsets
mod appr {
    pub const DISC: usize = 0;
    pub const ROOT: usize = 8;
    pub const DESTINATION: usize = 40;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn setup_mollusk() -> Mollusk {
    let pid = program_id();
    let mut mollusk = Mollusk::new(&pid, "veil_hook");
    // Set clock to a known timestamp (2024-01-01 12:00:00 UTC)
    mollusk.sysvars.clock.unix_timestamp = 1704110400;
    mollusk
}

fn derive_policy_pda(mint: &Pubkey, owner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POLICY_SEED, mint.as_ref(), owner.as_ref()], &program_id())
}

fn derive_tracker_pda(mint: &Pubkey, owner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[TRACKER_SEED, mint.as_ref(), owner.as_ref()], &program_id())
}

fn derive_extra_metas_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EXTRA_METAS_SEED, mint.as_ref()], &program_id())
}

fn derive_approval_pda(mint: &Pubkey, owner: &Pubkey, destination: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[APPROVAL_SEED, mint.as_ref(), owner.as_ref(), destination.as_ref()],
        &program_id(),
    )
}

/// SHA256 hash (test-side, using sha2 crate).
fn test_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Build a 2-leaf Merkle tree and return (root, proof_for_leaf0, proof_for_leaf1).
/// Each proof is encoded as `[proof_len, (position, sibling)...]` for instruction data.
fn build_merkle_2(dest0: &Pubkey, dest1: &Pubkey) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let leaf0 = test_sha256(dest0.as_ref());
    let leaf1 = test_sha256(dest1.as_ref());
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(&leaf0);
    combined[32..64].copy_from_slice(&leaf1);
    let root = test_sha256(&combined);

    // Proof for dest0: position=0 (left), sibling=leaf1
    let mut proof0 = vec![1u8]; // proof_len = 1
    proof0.push(0); // position
    proof0.extend_from_slice(&leaf1);

    // Proof for dest1: position=1 (right), sibling=leaf0
    let mut proof1 = vec![1u8]; // proof_len = 1
    proof1.push(1); // position
    proof1.extend_from_slice(&leaf0);

    (root, proof0, proof1)
}

/// Build a pre-populated approval PDA account.
fn make_approval_account(root: &[u8; 32], destination: &Pubkey) -> Account {
    let pid = program_id();
    let mut data = vec![0u8; APPROVAL_SIZE];
    data[appr::DISC..appr::DISC + 8].copy_from_slice(APPROVAL_DISC);
    data[appr::ROOT..appr::ROOT + 32].copy_from_slice(root);
    data[appr::DESTINATION..appr::DESTINATION + 32].copy_from_slice(destination.as_ref());
    let rent = Rent::default();
    Account {
        lamports: rent.minimum_balance(APPROVAL_SIZE),
        data,
        owner: pid,
        executable: false,
        rent_epoch: 0,
    }
}

/// Build CreatePolicy instruction data (31 bytes).
fn create_policy_data(
    tx_cap: u64,
    daily_cap: u64,
    monthly_cap: u64,
    velocity_max: u16,
    velocity_window: u16,
    time_start_h: u8,
    time_end_h: u8,
    mode: u8,
) -> Vec<u8> {
    let mut data = vec![CREATE_POLICY];
    data.extend_from_slice(&tx_cap.to_le_bytes());
    data.extend_from_slice(&daily_cap.to_le_bytes());
    data.extend_from_slice(&monthly_cap.to_le_bytes());
    data.extend_from_slice(&velocity_max.to_le_bytes());
    data.extend_from_slice(&velocity_window.to_le_bytes());
    data.push(time_start_h);
    data.push(time_end_h);
    data.push(mode);
    data
}

fn new_account(lamports: u64, space: usize, owner: &Pubkey) -> Account {
    Account {
        lamports,
        data: vec![0u8; space],
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

/// Create a mock SPL Token account with `token_owner` at bytes 32..64.
fn make_source_token_account(token_owner: &Pubkey, mint: &Pubkey) -> Account {
    let mut data = vec![0u8; 165]; // standard SPL Token account size
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(token_owner.as_ref());
    data[108] = 1; // AccountState::Initialized
    Account {
        lamports: 1_000_000,
        data,
        owner: Pubkey::default(),
        executable: false,
        rent_epoch: 0,
    }
}

/// Build a pre-populated policy account for Execute tests.
fn make_policy_account(
    owner: &Pubkey,
    mint: &Pubkey,
    tx_cap: u64,
    daily_cap: u64,
    monthly_cap: u64,
    velocity_max: u16,
    velocity_window: u16,
    time_start_h: u8,
    time_end_h: u8,
    mode: u8,
) -> Account {
    let pid = program_id();
    let mut data = vec![0u8; POLICY_SIZE];
    data[pol::DISC..pol::DISC + 8].copy_from_slice(POLICY_DISC);
    data[pol::OWNER..pol::OWNER + 32].copy_from_slice(owner.as_ref());
    data[pol::MINT..pol::MINT + 32].copy_from_slice(mint.as_ref());
    data[pol::TX_CAP..pol::TX_CAP + 8].copy_from_slice(&tx_cap.to_le_bytes());
    data[pol::DAILY_CAP..pol::DAILY_CAP + 8].copy_from_slice(&daily_cap.to_le_bytes());
    data[pol::MONTHLY_CAP..pol::MONTHLY_CAP + 8].copy_from_slice(&monthly_cap.to_le_bytes());
    data[pol::VELOCITY_MAX..pol::VELOCITY_MAX + 2].copy_from_slice(&velocity_max.to_le_bytes());
    data[pol::VELOCITY_WINDOW..pol::VELOCITY_WINDOW + 2]
        .copy_from_slice(&velocity_window.to_le_bytes());
    data[pol::TIME_START_H] = time_start_h;
    data[pol::TIME_END_H] = time_end_h;
    data[pol::MODE] = mode;

    let rent = Rent::default();
    Account {
        lamports: rent.minimum_balance(POLICY_SIZE),
        data,
        owner: pid,
        executable: false,
        rent_epoch: 0,
    }
}

/// Build a pre-populated policy account with a delegation slot.
fn make_policy_with_delegation(
    owner: &Pubkey,
    mint: &Pubkey,
    tx_cap: u64,
    daily_cap: u64,
    monthly_cap: u64,
    delegate: &Pubkey,
    delegate_daily_cap: u64,
    delegate_tx_cap: u64,
) -> Account {
    let mut acct = make_policy_account(owner, mint, tx_cap, daily_cap, monthly_cap, 0, 0, 0, 0, 2);
    let d = &mut acct.data;
    d[pol::DELEGATIONS_LEN] = 1;
    let base = pol::DELEGATIONS;
    d[base..base + 32].copy_from_slice(delegate.as_ref());
    d[base + deleg::DAILY_CAP..base + deleg::DAILY_CAP + 8]
        .copy_from_slice(&delegate_daily_cap.to_le_bytes());
    d[base + deleg::TX_CAP..base + deleg::TX_CAP + 8]
        .copy_from_slice(&delegate_tx_cap.to_le_bytes());
    acct
}

/// Build a pre-populated tracker account for Execute tests.
fn make_tracker_account(
    daily_spent: u64,
    monthly_spent: u64,
    now: i64,
    velocity_count: u16,
    tx_count_total: u64,
) -> Account {
    let pid = program_id();
    let mut data = vec![0u8; TRACKER_SIZE];
    data[trk::DISC..trk::DISC + 8].copy_from_slice(TRACKER_DISC);
    data[trk::DAILY_SPENT..trk::DAILY_SPENT + 8].copy_from_slice(&daily_spent.to_le_bytes());
    data[trk::MONTHLY_SPENT..trk::MONTHLY_SPENT + 8]
        .copy_from_slice(&monthly_spent.to_le_bytes());
    data[trk::DAILY_RESET_TS..trk::DAILY_RESET_TS + 8].copy_from_slice(&now.to_le_bytes());
    data[trk::MONTHLY_RESET_TS..trk::MONTHLY_RESET_TS + 8].copy_from_slice(&now.to_le_bytes());
    data[trk::VELOCITY_COUNT..trk::VELOCITY_COUNT + 2]
        .copy_from_slice(&velocity_count.to_le_bytes());
    data[trk::VELOCITY_WINDOW_START..trk::VELOCITY_WINDOW_START + 8]
        .copy_from_slice(&now.to_le_bytes());
    data[trk::TX_COUNT_TOTAL..trk::TX_COUNT_TOTAL + 8]
        .copy_from_slice(&tx_count_total.to_le_bytes());

    let rent = Rent::default();
    Account {
        lamports: rent.minimum_balance(TRACKER_SIZE),
        data,
        owner: pid,
        executable: false,
        rent_epoch: 0,
    }
}

/// Read a u64 from a byte slice at the given offset.
fn r64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// Read an i64 from a byte slice at the given offset.
fn ri64(data: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

/// Read a u16 from a byte slice at the given offset.
fn r16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

// ── CreatePolicy Tests ─────────────────────────────────────────────────────────

#[test]
fn test_create_policy_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    let ix_data = create_policy_data(1000, 10000, 50000, 5, 3600, 9, 17, 2);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, Account::default()),
        (tracker_pda, Account::default()),
        (sys, system_program_account()),
    ];

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[
            Check::success(),
            Check::account(&policy_pda)
                .owner(&pid)
                .space(POLICY_SIZE)
                .build(),
            Check::account(&tracker_pda)
                .owner(&pid)
                .space(TRACKER_SIZE)
                .build(),
        ],
    );

    // Verify policy data contents
    let policy_account = result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == policy_pda)
        .unwrap()
        .1
        .clone();
    let d = &policy_account.data;
    assert_eq!(&d[pol::DISC..pol::DISC + 8], POLICY_DISC);
    assert_eq!(&d[pol::OWNER..pol::OWNER + 32], owner.as_ref());
    assert_eq!(&d[pol::MINT..pol::MINT + 32], mint.as_ref());
    assert_eq!(r64(d, pol::TX_CAP), 1000);
    assert_eq!(r64(d, pol::DAILY_CAP), 10000);
    assert_eq!(r64(d, pol::MONTHLY_CAP), 50000);
    assert_eq!(r16(d, pol::VELOCITY_MAX), 5);
    assert_eq!(r16(d, pol::VELOCITY_WINDOW), 3600);
    assert_eq!(d[pol::TIME_START_H], 9);
    assert_eq!(d[pol::TIME_END_H], 17);
    assert_eq!(d[pol::MODE], 2);

    // Verify tracker initialization
    let tracker_account = result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .clone();
    let t = &tracker_account.data;
    assert_eq!(&t[trk::DISC..trk::DISC + 8], TRACKER_DISC);
    assert_eq!(r64(t, trk::DAILY_SPENT), 0);
    assert_eq!(r64(t, trk::MONTHLY_SPENT), 0);
    let now = mollusk.sysvars.clock.unix_timestamp;
    assert_eq!(ri64(t, trk::DAILY_RESET_TS), now);
    assert_eq!(ri64(t, trk::MONTHLY_RESET_TS), now);
}

#[test]
fn test_create_policy_already_initialized() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    let ix_data = create_policy_data(1000, 10000, 50000, 5, 3600, 0, 0, 2);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    // Policy PDA already has data (non-empty)
    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, new_account(1_000_000, POLICY_SIZE, &pid)),
        (tracker_pda, Account::default()),
        (sys, system_program_account()),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_ALREADY_INITIALIZED))],
    );
}

#[test]
fn test_create_policy_missing_signer() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    let ix_data = create_policy_data(1000, 10000, 50000, 5, 3600, 0, 0, 2);

    // Owner is NOT a signer
    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, false), // not signer!
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, Account::default()),
        (tracker_pda, Account::default()),
        (sys, system_program_account()),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}

#[test]
fn test_create_policy_invalid_mode() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    // mode = 3 is invalid
    let ix_data = create_policy_data(1000, 10000, 50000, 5, 3600, 0, 0, 3);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, Account::default()),
        (tracker_pda, Account::default()),
        (sys, system_program_account()),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ── UpdatePolicy Tests ─────────────────────────────────────────────────────────

#[test]
fn test_update_policy_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);

    let policy_account = make_policy_account(&owner, &mint, 1000, 10000, 50000, 5, 3600, 0, 0, 2);

    // Update to new caps
    let mut ix_data = vec![UPDATE_POLICY];
    ix_data.extend_from_slice(&2000u64.to_le_bytes());
    ix_data.extend_from_slice(&20000u64.to_le_bytes());
    ix_data.extend_from_slice(&100000u64.to_le_bytes());
    ix_data.extend_from_slice(&10u16.to_le_bytes());
    ix_data.extend_from_slice(&1800u16.to_le_bytes());
    ix_data.push(8);
    ix_data.push(20);
    ix_data.push(1);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(policy_pda, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(1_000_000, 0, &sys)),
        (policy_pda, policy_account),
    ];

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == policy_pda)
        .unwrap()
        .1
        .data;

    assert_eq!(r64(d, pol::TX_CAP), 2000);
    assert_eq!(r64(d, pol::DAILY_CAP), 20000);
    assert_eq!(r64(d, pol::MONTHLY_CAP), 100000);
    assert_eq!(r16(d, pol::VELOCITY_MAX), 10);
    assert_eq!(r16(d, pol::VELOCITY_WINDOW), 1800);
    assert_eq!(d[pol::TIME_START_H], 8);
    assert_eq!(d[pol::TIME_END_H], 20);
    assert_eq!(d[pol::MODE], 1);
}

#[test]
fn test_update_policy_wrong_owner() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);

    let policy_account = make_policy_account(&owner, &mint, 1000, 10000, 50000, 5, 3600, 0, 0, 2);

    let mut ix_data = vec![UPDATE_POLICY];
    ix_data.extend_from_slice(&[0u8; 31]);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new_readonly(attacker, true),
            AccountMeta::new(policy_pda, false),
        ],
    );

    let accounts = vec![
        (attacker, new_account(1_000_000, 0, &sys)),
        (policy_pda, policy_account),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_NOT_POLICY_OWNER))],
    );
}

// ── AddDelegation Tests ────────────────────────────────────────────────────────

#[test]
fn test_add_delegation_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let delegate = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);

    let policy_account = make_policy_account(&owner, &mint, 1000, 10000, 50000, 5, 3600, 0, 0, 2);

    let mut ix_data = vec![ADD_DELEGATION];
    ix_data.extend_from_slice(delegate.as_ref());
    ix_data.extend_from_slice(&5000u64.to_le_bytes());
    ix_data.extend_from_slice(&500u64.to_le_bytes());

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(policy_pda, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(1_000_000, 0, &sys)),
        (policy_pda, policy_account),
    ];

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == policy_pda)
        .unwrap()
        .1
        .data;

    assert_eq!(d[pol::DELEGATIONS_LEN], 1);
    let base = pol::DELEGATIONS;
    assert_eq!(&d[base..base + 32], delegate.as_ref());
    assert_eq!(r64(d, base + 32), 5000);
    assert_eq!(r64(d, base + 40), 500);
}

// ── Execute Tests ──────────────────────────────────────────────────────────────

/// Build the account list for an Execute instruction.
/// `token_owner` is embedded in the source token account data at bytes 32..64.
/// Includes the approval PDA (phantom by default for non-whitelist tests).
fn setup_execute_accounts(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    extra_metas_pda: &Pubkey,
    policy_pda: &Pubkey,
    tracker_pda: &Pubkey,
    token_owner: &Pubkey,
    policy_account: Account,
    tracker_account: Account,
) -> Vec<(Pubkey, Account)> {
    let pid = program_id();
    let sys = system_program_id();
    let (approval_pda, _) = derive_approval_pda(mint, token_owner, destination);
    vec![
        (*source, make_source_token_account(token_owner, mint)),
        (*mint, new_account(1_000_000, 0, &Pubkey::default())),
        (*destination, new_account(1_000_000, 0, &Pubkey::default())),
        (*authority, new_account(1_000_000, 0, &sys)),
        (
            *extra_metas_pda,
            new_account(1_000_000, EXTRA_METAS_DATA_SIZE, &pid),
        ),
        (*policy_pda, policy_account),
        (*tracker_pda, tracker_account),
        (approval_pda, Account::default()), // phantom approval PDA
    ]
}

/// Like setup_execute_accounts but with a real approval PDA account.
fn setup_execute_accounts_with_approval(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    extra_metas_pda: &Pubkey,
    policy_pda: &Pubkey,
    tracker_pda: &Pubkey,
    token_owner: &Pubkey,
    policy_account: Account,
    tracker_account: Account,
    approval_account: Account,
) -> Vec<(Pubkey, Account)> {
    let pid = program_id();
    let sys = system_program_id();
    let (approval_pda, _) = derive_approval_pda(mint, token_owner, destination);
    vec![
        (*source, make_source_token_account(token_owner, mint)),
        (*mint, new_account(1_000_000, 0, &Pubkey::default())),
        (*destination, new_account(1_000_000, 0, &Pubkey::default())),
        (*authority, new_account(1_000_000, 0, &sys)),
        (
            *extra_metas_pda,
            new_account(1_000_000, EXTRA_METAS_DATA_SIZE, &pid),
        ),
        (*policy_pda, policy_account),
        (*tracker_pda, tracker_account),
        (approval_pda, approval_account),
    ]
}

fn execute_instruction(amount: u64) -> Vec<u8> {
    let mut data = EXECUTE_DISC.to_vec();
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn execute_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    extra_metas_pda: &Pubkey,
    policy_pda: &Pubkey,
    tracker_pda: &Pubkey,
    token_owner: &Pubkey,
    amount: u64,
) -> Instruction {
    let (approval_pda, _) = derive_approval_pda(mint, token_owner, destination);
    Instruction::new_with_bytes(
        program_id(),
        &execute_instruction(amount),
        vec![
            AccountMeta::new_readonly(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*destination, false),
            AccountMeta::new_readonly(*authority, false),
            AccountMeta::new_readonly(*extra_metas_pda, false),
            AccountMeta::new_readonly(*policy_pda, false),
            AccountMeta::new(*tracker_pda, false),
            AccountMeta::new_readonly(approval_pda, false),
        ],
    )
}

#[test]
fn test_execute_basic_transfer() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique(); // authority = token owner
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 1000, 10000, 50000, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 500,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, // token_owner = authority
        policy, tracker,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r64(t, trk::DAILY_SPENT), 500);
    assert_eq!(r64(t, trk::MONTHLY_SPENT), 500);
    assert_eq!(r64(t, trk::TX_COUNT_TOTAL), 1);
}

#[test]
fn test_execute_tx_cap_exceeded() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 1000, 0, 0, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 1001,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_AMOUNT_EXCEEDS_TX_CAP))],
    );
}

#[test]
fn test_execute_daily_cap_exceeded() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 0, 10000, 0, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(9500, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 501,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_DAILY_CAP_EXCEEDED))],
    );
}

#[test]
fn test_execute_monthly_cap_exceeded() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 0, 0, 50000, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(0, 49900, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 101,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_MONTHLY_CAP_EXCEEDED))],
    );
}

#[test]
fn test_execute_velocity_limit() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // velocity_max = 3, velocity_window = 3600s, already did 3 txs
    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 3, 3600, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, now, 3, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 1,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_VELOCITY_LIMIT_EXCEEDED))],
    );
}

#[test]
fn test_execute_velocity_window_reset() {
    let mut mollusk = setup_mollusk();
    let window_start = 1704110400i64;
    mollusk.sysvars.clock.unix_timestamp = window_start + 7200; // 2h later

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // velocity_max = 3, window = 3600s, already 3 txs — but window expired
    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 3, 3600, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, window_start, 3, 5);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 1,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r16(t, trk::VELOCITY_COUNT), 1);
    assert_eq!(r64(t, trk::TX_COUNT_TOTAL), 6);
}

#[test]
fn test_execute_time_window_violation() {
    let mut mollusk = setup_mollusk();
    // 2024-01-01 02:00 UTC (hour = 2)
    mollusk.sysvars.clock.unix_timestamp = 1704074400;
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // time_start=9, time_end=17 → allowed 09:00-16:59 UTC
    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 9, 17, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 1,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_TIME_WINDOW_VIOLATION))],
    );
}

#[test]
fn test_execute_time_window_allowed() {
    let mut mollusk = setup_mollusk();
    // 2024-01-01 12:00 UTC (hour = 12)
    mollusk.sysvars.clock.unix_timestamp = 1704110400;
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 9, 17, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn test_execute_unauthorized_wallet() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let unauthorized = Pubkey::new_unique();

    // PDAs are keyed to the token owner, not the unauthorized authority
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    // Policy owned by `owner`, no delegations
    let policy = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &unauthorized,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, 1,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &unauthorized,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, // token_owner = owner (not unauthorized)
        policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_DELEGATION_UNAUTHORIZED))],
    );
}

#[test]
fn test_execute_delegate_transfer() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let delegate = Pubkey::new_unique();

    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    // Global caps: tx=1000, daily=10000, monthly=50000
    // Delegate sub-caps: daily=5000, tx=500
    let policy = make_policy_with_delegation(
        &owner, &mint, 1000, 10000, 50000,
        &delegate, 5000, 500,
    );
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    // Delegate transfers 400 (within delegate tx_cap of 500)
    let instruction = execute_ix(
        &source, &mint, &destination, &delegate,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, 400,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &delegate,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, // token_owner = owner, authority = delegate
        policy, tracker,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r64(t, trk::DAILY_SPENT), 400);
    assert_eq!(r64(t, trk::MONTHLY_SPENT), 400);
    assert_eq!(r64(t, trk::TX_COUNT_TOTAL), 1);
}

#[test]
fn test_execute_delegate_tx_cap_exceeded() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let delegate = Pubkey::new_unique();

    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &owner);

    // Delegate tx_cap = 500, global tx_cap = 1000
    // Effective tx_cap = min(500, 1000) = 500
    let policy = make_policy_with_delegation(
        &owner, &mint, 1000, 10000, 50000,
        &delegate, 5000, 500,
    );
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    // Delegate tries 501 — exceeds delegate tx_cap
    let instruction = execute_ix(
        &source, &mint, &destination, &delegate,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, 501,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &delegate,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &owner, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_AMOUNT_EXCEEDS_TX_CAP))],
    );
}

#[test]
fn test_execute_daily_reset_after_24h() {
    let mut mollusk = setup_mollusk();
    let old_ts = 1704000000i64;
    mollusk.sysvars.clock.unix_timestamp = old_ts + 90000; // 25h later
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // daily_cap = 10000, already spent 9999 — but reset_ts is old
    let policy = make_policy_account(&authority, &mint, 0, 10000, 0, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(9999, 0, old_ts, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 5000,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r64(t, trk::DAILY_SPENT), 5000);
    assert_eq!(ri64(t, trk::DAILY_RESET_TS), now);
}

#[test]
fn test_execute_cumulative_tracking() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 0, 100000, 500000, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(3000, 15000, now, 0, 7);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 2000,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r64(t, trk::DAILY_SPENT), 5000);
    assert_eq!(r64(t, trk::MONTHLY_SPENT), 17000);
    assert_eq!(r64(t, trk::TX_COUNT_TOTAL), 8);
}

#[test]
fn test_execute_whitelist_rejects_with_root() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // mode=0 (whitelist) with a non-zero root → should reject
    let mut policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    // Set a fake whitelist root (non-zero)
    policy.data[pol::WHITELIST_ROOT] = 0xAB;
    policy.data[pol::WHITELIST_ROOT + 1] = 0xCD;
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_RECIPIENT_NOT_WHITELISTED))],
    );
}

#[test]
fn test_execute_whitelist_allows_with_zero_root() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // mode=0 (whitelist) with zero root → no whitelist configured, allow
    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

// ── InitExtraAccountMetas Tests ────────────────────────────────────────────────

#[test]
fn test_init_extra_account_metas_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let mint = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);

    let ix_data = INIT_EXTRA_METAS_DISC.to_vec();

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(extra_metas_pda, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (extra_metas_pda, Account::default()),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (authority, new_account(10_000_000_000, 0, &sys)),
        (sys, system_program_account()),
    ];

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[
            Check::success(),
            Check::account(&extra_metas_pda)
                .owner(&pid)
                .space(EXTRA_METAS_DATA_SIZE)
                .build(),
        ],
    );

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == extra_metas_pda)
        .unwrap()
        .1
        .data;

    // TLV header
    assert_eq!(&d[0..8], &EXECUTE_DISC);
    assert_eq!(u32::from_le_bytes(d[8..12].try_into().unwrap()), 109); // 4 + 3*35
    assert_eq!(u32::from_le_bytes(d[12..16].try_into().unwrap()), 3);

    // Entry 0: Policy PDA, disc=1, read-only
    assert_eq!(d[16], 1); // PDA discriminator
    // Seed encoding: literal "policy" + account_key(1) + account_data(0, 32, 32)
    assert_eq!(d[17], 1);  // seed type: literal
    assert_eq!(d[18], 6);  // literal length
    assert_eq!(&d[19..25], b"policy");
    assert_eq!(d[25], 3);  // seed type: account_key
    assert_eq!(d[26], 1);  // account index (mint)
    assert_eq!(d[27], 4);  // seed type: account_data
    assert_eq!(d[28], 0);  // account index (source)
    assert_eq!(d[29], 32); // data offset (owner field)
    assert_eq!(d[30], 32); // data length (pubkey size)
    assert_eq!(d[16 + 33], 0); // is_signer
    assert_eq!(d[16 + 34], 0); // is_writable

    // Entry 1: Tracker PDA, disc=1, writable
    assert_eq!(d[51], 1); // PDA discriminator
    // Seed encoding: literal "tracker" + account_key(1) + account_data(0, 32, 32)
    assert_eq!(d[52], 1);  // seed type: literal
    assert_eq!(d[53], 7);  // literal length
    assert_eq!(&d[54..61], b"tracker");
    assert_eq!(d[61], 3);  // seed type: account_key
    assert_eq!(d[62], 1);  // account index (mint)
    assert_eq!(d[63], 4);  // seed type: account_data
    assert_eq!(d[64], 0);  // account index (source)
    assert_eq!(d[65], 32); // data offset
    assert_eq!(d[66], 32); // data length
    assert_eq!(d[51 + 33], 0); // is_signer
    assert_eq!(d[51 + 34], 1); // is_writable

    // Entry 2: Approval PDA, disc=1, read-only
    assert_eq!(d[86], 1); // PDA discriminator
    // Seed encoding: literal "approval" + account_key(1) + account_data(0, 32, 32) + account_key(2)
    assert_eq!(d[87], 1);  // seed type: literal
    assert_eq!(d[88], 8);  // literal length
    assert_eq!(&d[89..97], b"approval");
    assert_eq!(d[97], 3);  // seed type: account_key
    assert_eq!(d[98], 1);  // account index (mint)
    assert_eq!(d[99], 4);  // seed type: account_data
    assert_eq!(d[100], 0); // account index (source)
    assert_eq!(d[101], 32); // data offset (owner field)
    assert_eq!(d[102], 32); // data length
    assert_eq!(d[103], 3);  // seed type: account_key
    assert_eq!(d[104], 2);  // account index (destination)
    assert_eq!(d[86 + 33], 0); // is_signer
    assert_eq!(d[86 + 34], 0); // is_writable
}

#[test]
fn test_init_extra_account_metas_already_initialized() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let mint = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);

    let ix_data = INIT_EXTRA_METAS_DISC.to_vec();

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(extra_metas_pda, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(authority, true),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (
            extra_metas_pda,
            new_account(1_000_000, EXTRA_METAS_DATA_SIZE, &pid),
        ),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (authority, new_account(10_000_000_000, 0, &sys)),
        (sys, system_program_account()),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_ALREADY_INITIALIZED))],
    );
}

// ── Edge Case Tests ────────────────────────────────────────────────────────────

#[test]
fn test_execute_zero_caps_means_unlimited() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    let policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, u64::MAX / 2,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn test_execute_exact_cap_boundary() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // tx_cap=1000, daily=5000, monthly=10000
    let policy = make_policy_account(&authority, &mint, 1000, 5000, 10000, 0, 0, 0, 0, 2);
    let tracker = make_tracker_account(4000, 9000, now, 0, 0);

    // Exactly at all boundaries
    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 1000,
    );

    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn test_invalid_instruction_discriminator() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();

    let instruction = Instruction::new_with_bytes(
        pid,
        &[0xFF],
        vec![AccountMeta::new(owner, true)],
    );

    let accounts = vec![(owner, new_account(1_000_000, 0, &sys))];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ── SetWhitelistRoot Tests ───────────────────────────────────────────────────

#[test]
fn test_set_whitelist_root_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);

    let policy_account = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 0);

    let root = [0xABu8; 32];
    let mut ix_data = vec![SET_WHITELIST_ROOT];
    ix_data.extend_from_slice(&root);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new_readonly(owner, true),
            AccountMeta::new(policy_pda, false),
        ],
    );

    let sys = system_program_id();
    let accounts = vec![
        (owner, new_account(1_000_000, 0, &sys)),
        (policy_pda, policy_account),
    ];

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == policy_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(&d[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32], &root);
}

#[test]
fn test_set_whitelist_root_wrong_owner() {
    let mollusk = setup_mollusk();
    let pid = program_id();

    let owner = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);

    let policy_account = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 0);

    let mut ix_data = vec![SET_WHITELIST_ROOT];
    ix_data.extend_from_slice(&[0xAB; 32]);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new_readonly(attacker, true),
            AccountMeta::new(policy_pda, false),
        ],
    );

    let sys = system_program_id();
    let accounts = vec![
        (attacker, new_account(1_000_000, 0, &sys)),
        (policy_pda, policy_account),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_NOT_POLICY_OWNER))],
    );
}

// ── ApproveDestination Tests ─────────────────────────────────────────────────

#[test]
fn test_approve_destination_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let dest0 = Pubkey::new_unique();
    let dest1 = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (approval_pda, _) = derive_approval_pda(&mint, &owner, &dest0);

    // Build Merkle tree with 2 destinations
    let (root, proof0, _proof1) = build_merkle_2(&dest0, &dest1);

    // Create policy with whitelist root set
    let mut policy = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32].copy_from_slice(&root);

    let mut ix_data = vec![APPROVE_DESTINATION];
    ix_data.extend_from_slice(&proof0);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(policy_pda, false),
            AccountMeta::new_readonly(dest0, false),
            AccountMeta::new(approval_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, policy),
        (dest0, new_account(1_000_000, 0, &Pubkey::default())),
        (approval_pda, Account::default()),
        (sys, system_program_account()),
    ];

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[
            Check::success(),
            Check::account(&approval_pda)
                .owner(&pid)
                .space(APPROVAL_SIZE)
                .build(),
        ],
    );

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == approval_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(&d[appr::DISC..appr::DISC + 8], APPROVAL_DISC);
    assert_eq!(&d[appr::ROOT..appr::ROOT + 32], &root);
    assert_eq!(&d[appr::DESTINATION..appr::DESTINATION + 32], dest0.as_ref());
}

#[test]
fn test_approve_destination_invalid_proof() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let dest0 = Pubkey::new_unique();
    let dest1 = Pubkey::new_unique();
    let not_in_tree = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (approval_pda, _) = derive_approval_pda(&mint, &owner, &not_in_tree);

    // Build Merkle tree with dest0 and dest1
    let (root, proof0, _) = build_merkle_2(&dest0, &dest1);

    let mut policy = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32].copy_from_slice(&root);

    // Try to approve `not_in_tree` using dest0's proof — proof should fail
    let mut ix_data = vec![APPROVE_DESTINATION];
    ix_data.extend_from_slice(&proof0);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(policy_pda, false),
            AccountMeta::new_readonly(not_in_tree, false),
            AccountMeta::new(approval_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, policy),
        (not_in_tree, new_account(1_000_000, 0, &Pubkey::default())),
        (approval_pda, Account::default()),
        (sys, system_program_account()),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_INVALID_MERKLE_PROOF))],
    );
}

// ── Execute + Whitelist Approval Tests ───────────────────────────────────────

#[test]
fn test_execute_whitelist_with_approval() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique(); // = token_owner
    let dest1 = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // Build tree with destination + dest1
    let (root, _proof0, _) = build_merkle_2(&destination, &dest1);

    // mode=0, whitelist root set
    let mut policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32].copy_from_slice(&root);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    // Pre-populate approval PDA with matching root
    let approval = make_approval_account(&root, &destination);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    let accounts = setup_execute_accounts_with_approval(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker, approval,
    );

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let t = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == tracker_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(r64(t, trk::DAILY_SPENT), 100);
    assert_eq!(r64(t, trk::TX_COUNT_TOTAL), 1);
}

#[test]
fn test_execute_whitelist_no_approval() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // mode=0, whitelist root set, NO approval PDA exists
    let mut policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT] = 0xAB;
    policy.data[pol::WHITELIST_ROOT + 1] = 0xCD;
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    // setup_execute_accounts uses Account::default() for approval (phantom)
    let accounts = setup_execute_accounts(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_RECIPIENT_NOT_WHITELISTED))],
    );
}

#[test]
fn test_execute_whitelist_stale_approval() {
    let mollusk = setup_mollusk();
    let now = mollusk.sysvars.clock.unix_timestamp;

    let source = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let (extra_metas_pda, _) = derive_extra_metas_pda(&mint);
    let (policy_pda, _) = derive_policy_pda(&mint, &authority);
    let (tracker_pda, _) = derive_tracker_pda(&mint, &authority);

    // Current policy root
    let new_root = [0xBB; 32];

    // mode=0, whitelist root set to new_root
    let mut policy = make_policy_account(&authority, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32].copy_from_slice(&new_root);
    let tracker = make_tracker_account(0, 0, now, 0, 0);

    // Approval PDA has OLD root (different from policy's current root)
    let old_root = [0xAA; 32];
    let approval = make_approval_account(&old_root, &destination);

    let instruction = execute_ix(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, 100,
    );

    let accounts = setup_execute_accounts_with_approval(
        &source, &mint, &destination, &authority,
        &extra_metas_pda, &policy_pda, &tracker_pda,
        &authority, policy, tracker, approval,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(ERR_RECIPIENT_NOT_WHITELISTED))],
    );
}

// ── RevokeApproval Tests ─────────────────────────────────────────────────────

#[test]
fn test_revoke_approval_success() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let (approval_pda, _) = derive_approval_pda(&mint, &owner, &destination);

    let root = [0xAB; 32];
    let approval = make_approval_account(&root, &destination);
    let approval_lamports = approval.lamports;

    let owner_initial_lamports = 1_000_000u64;

    let ix_data = vec![REVOKE_APPROVAL];

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(destination, false),
            AccountMeta::new(approval_pda, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(owner_initial_lamports, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (destination, new_account(1_000_000, 0, &Pubkey::default())),
        (approval_pda, approval),
    ];

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    // Check that approval PDA is closed (0 lamports, zeroed data)
    let appr_result = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == approval_pda)
        .unwrap()
        .1;
    assert_eq!(appr_result.lamports, 0);
    assert!(appr_result.data.iter().all(|&b| b == 0));

    // Check owner received the lamports
    let owner_result = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == owner)
        .unwrap()
        .1;
    assert_eq!(owner_result.lamports, owner_initial_lamports + approval_lamports);
}

// ── Approve Second Destination (Right Leaf) Test ─────────────────────────────

#[test]
fn test_approve_second_destination() {
    let mollusk = setup_mollusk();
    let pid = program_id();
    let sys = system_program_id();

    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let dest0 = Pubkey::new_unique();
    let dest1 = Pubkey::new_unique();
    let (policy_pda, _) = derive_policy_pda(&mint, &owner);
    let (approval_pda, _) = derive_approval_pda(&mint, &owner, &dest1);

    let (root, _proof0, proof1) = build_merkle_2(&dest0, &dest1);

    let mut policy = make_policy_account(&owner, &mint, 0, 0, 0, 0, 0, 0, 0, 0);
    policy.data[pol::WHITELIST_ROOT..pol::WHITELIST_ROOT + 32].copy_from_slice(&root);

    let mut ix_data = vec![APPROVE_DESTINATION];
    ix_data.extend_from_slice(&proof1);

    let instruction = Instruction::new_with_bytes(
        pid,
        &ix_data,
        vec![
            AccountMeta::new(owner, true),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(policy_pda, false),
            AccountMeta::new_readonly(dest1, false),
            AccountMeta::new(approval_pda, false),
            AccountMeta::new_readonly(sys, false),
        ],
    );

    let accounts = vec![
        (owner, new_account(10_000_000_000, 0, &sys)),
        (mint, new_account(1_000_000, 0, &Pubkey::default())),
        (policy_pda, policy),
        (dest1, new_account(1_000_000, 0, &Pubkey::default())),
        (approval_pda, Account::default()),
        (sys, system_program_account()),
    ];

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::success()],
    );

    let d = &result
        .resulting_accounts
        .iter()
        .find(|(k, _)| *k == approval_pda)
        .unwrap()
        .1
        .data;
    assert_eq!(&d[appr::DISC..appr::DISC + 8], APPROVAL_DISC);
    assert_eq!(&d[appr::ROOT..appr::ROOT + 32], &root);
    assert_eq!(&d[appr::DESTINATION..appr::DESTINATION + 32], dest1.as_ref());
}
