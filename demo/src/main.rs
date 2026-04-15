///! Veil Transfer Hook — Devnet Demo
///!
///! Creates a Token-2022 mint with transfer hook, exercises every feature,
///! and prints Solscan links for each transaction.

use sha2::{Sha256, Digest};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction,
    system_program,
    transaction::Transaction,
};
use spl_token_2022::solana_program::program_pack::Pack;
use spl_associated_token_account::{
    get_associated_token_address_with_program_id,
    instruction::create_associated_token_account,
};
use std::str::FromStr;

// ── Program + constants ─────────────────────────────────────────────────────

const PROGRAM_ID: &str = "J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SPL_ATA: &str     = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const POLICY_SEED: &[u8] = b"policy";
const TRACKER_SEED: &[u8] = b"tracker";
const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";
const APPROVAL_SEED: &[u8] = b"approval";

const EXECUTE_DISC: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
const INIT_EXTRA_DISC: [u8; 8] = [43, 34, 13, 49, 167, 88, 235, 235];

const CREATE_POLICY: u8 = 0x00;
const UPDATE_POLICY: u8 = 0x01;
const ADD_DELEGATION: u8 = 0x02;
const SET_WHITELIST_ROOT: u8 = 0x03;
const APPROVE_DESTINATION: u8 = 0x04;
const REVOKE_APPROVAL: u8 = 0x05;

fn program_id() -> Pubkey { Pubkey::from_str(PROGRAM_ID).unwrap() }
fn token_2022() -> Pubkey { Pubkey::from_str(TOKEN_2022).unwrap() }
fn spl_ata() -> Pubkey { Pubkey::from_str(SPL_ATA).unwrap() }

fn solscan(sig: &str) -> String {
    format!("https://solscan.io/tx/{}?cluster=devnet", sig)
}

fn derive_pda(seeds: &[&[u8]]) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, &program_id())
}

// ── Merkle helpers ──────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Build a 2-leaf Merkle tree. Returns (root, proof_for_leaf0, proof_for_leaf1).
/// proof = [(position, sibling_hash)]
fn build_merkle_2(leaf0: &[u8; 32], leaf1: &[u8; 32]) -> ([u8; 32], Vec<(u8, [u8; 32])>, Vec<(u8, [u8; 32])>) {
    let h0 = sha256(leaf0);
    let h1 = sha256(leaf1);
    let mut combined = [0u8; 64];
    // Sort: smaller hash first for canonical ordering
    if h0 <= h1 {
        combined[..32].copy_from_slice(&h0);
        combined[32..].copy_from_slice(&h1);
        let root = sha256(&combined);
        // proof for leaf0: sibling is h1, leaf0 is left (position=0)
        // proof for leaf1: sibling is h0, leaf1 is right (position=1)
        (root, vec![(0, h1)], vec![(1, h0)])
    } else {
        combined[..32].copy_from_slice(&h1);
        combined[32..].copy_from_slice(&h0);
        let root = sha256(&combined);
        // proof for leaf0: sibling is h1, leaf0 is right (position=1)
        // proof for leaf1: sibling is h0, leaf1 is left (position=0)
        (root, vec![(1, h1)], vec![(0, h0)])
    }
}

fn encode_proof(proof: &[(u8, [u8; 32])]) -> Vec<u8> {
    let mut data = vec![proof.len() as u8];
    for (pos, hash) in proof {
        data.push(*pos);
        data.extend_from_slice(hash);
    }
    data
}

// ── Instruction builders ────────────────────────────────────────────────────

fn ix_init_extra_metas(payer: &Pubkey, mint: &Pubkey) -> Instruction {
    let (extra_metas_pda, _) = derive_pda(&[EXTRA_METAS_SEED, mint.as_ref()]);
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&INIT_EXTRA_DISC);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(extra_metas_pda, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn ix_create_policy(
    owner: &Pubkey,
    mint: &Pubkey,
    tx_cap: u64,
    daily_cap: u64,
    monthly_cap: u64,
    velocity_max: u16,
    velocity_window: u16,
    time_start: u8,
    time_end: u8,
    mode: u8,
) -> Instruction {
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), owner.as_ref()]);
    let (tracker_pda, _) = derive_pda(&[TRACKER_SEED, mint.as_ref(), owner.as_ref()]);

    let mut data = vec![CREATE_POLICY];
    data.extend_from_slice(&tx_cap.to_le_bytes());
    data.extend_from_slice(&daily_cap.to_le_bytes());
    data.extend_from_slice(&monthly_cap.to_le_bytes());
    data.extend_from_slice(&velocity_max.to_le_bytes());
    data.extend_from_slice(&velocity_window.to_le_bytes());
    data.push(time_start);
    data.push(time_end);
    data.push(mode);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn ix_update_policy(
    owner: &Pubkey,
    mint: &Pubkey,
    tx_cap: u64,
    daily_cap: u64,
    monthly_cap: u64,
    velocity_max: u16,
    velocity_window: u16,
    time_start: u8,
    time_end: u8,
    mode: u8,
) -> Instruction {
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), owner.as_ref()]);

    let mut data = vec![UPDATE_POLICY];
    data.extend_from_slice(&tx_cap.to_le_bytes());
    data.extend_from_slice(&daily_cap.to_le_bytes());
    data.extend_from_slice(&monthly_cap.to_le_bytes());
    data.extend_from_slice(&velocity_max.to_le_bytes());
    data.extend_from_slice(&velocity_window.to_le_bytes());
    data.push(time_start);
    data.push(time_end);
    data.push(mode);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(policy_pda, false),
        ],
        data,
    }
}

fn ix_add_delegation(
    owner: &Pubkey,
    mint: &Pubkey,
    delegate: &Pubkey,
    daily_cap: u64,
    tx_cap: u64,
) -> Instruction {
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), owner.as_ref()]);

    let mut data = vec![ADD_DELEGATION];
    data.extend_from_slice(delegate.as_ref());
    data.extend_from_slice(&daily_cap.to_le_bytes());
    data.extend_from_slice(&tx_cap.to_le_bytes());

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(policy_pda, false),
        ],
        data,
    }
}

fn ix_set_whitelist_root(
    owner: &Pubkey,
    mint: &Pubkey,
    root: &[u8; 32],
) -> Instruction {
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), owner.as_ref()]);

    let mut data = vec![SET_WHITELIST_ROOT];
    data.extend_from_slice(root);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(policy_pda, false),
        ],
        data,
    }
}

fn ix_approve_destination(
    owner: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    proof: &[(u8, [u8; 32])],
) -> Instruction {
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), owner.as_ref()]);
    let (approval_pda, _) = derive_pda(&[APPROVAL_SEED, mint.as_ref(), owner.as_ref(), destination.as_ref()]);

    let mut data = vec![APPROVE_DESTINATION];
    data.extend_from_slice(&encode_proof(proof));

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(policy_pda, false),
            AccountMeta::new_readonly(*destination, false),
            AccountMeta::new(approval_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

fn ix_revoke_approval(
    owner: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
) -> Instruction {
    let (approval_pda, _) = derive_pda(&[APPROVAL_SEED, mint.as_ref(), owner.as_ref(), destination.as_ref()]);

    let data = vec![REVOKE_APPROVAL];
    // no extra data needed

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*destination, false),
            AccountMeta::new(approval_pda, false),
        ],
        data,
    }
}

/// Build a Token-2022 TransferChecked instruction with the transfer hook extra accounts.
fn ix_transfer_checked_with_hook(
    source_ata: &Pubkey,
    mint: &Pubkey,
    dest_ata: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
    token_owner: &Pubkey,
) -> Instruction {
    let (extra_metas_pda, _) = derive_pda(&[EXTRA_METAS_SEED, mint.as_ref()]);
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), token_owner.as_ref()]);
    let (tracker_pda, _) = derive_pda(&[TRACKER_SEED, mint.as_ref(), token_owner.as_ref()]);
    let (approval_pda, _) = derive_pda(&[APPROVAL_SEED, mint.as_ref(), token_owner.as_ref(), dest_ata.as_ref()]);

    // Token-2022 TransferChecked instruction with additional accounts for hook
    // Disc: 12 (TransferChecked)
    let mut data = vec![12]; // TransferChecked instruction discriminator
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    let accounts = vec![
        AccountMeta::new(*source_ata, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new(*dest_ata, false),
        AccountMeta::new_readonly(*authority, true),
        // Extra accounts for transfer hook (appended by Token-2022 runtime):
        AccountMeta::new_readonly(extra_metas_pda, false),
        AccountMeta::new_readonly(policy_pda, false),
        AccountMeta::new(tracker_pda, false),
        AccountMeta::new_readonly(approval_pda, false),
        AccountMeta::new_readonly(program_id(), false),
    ];

    Instruction {
        program_id: token_2022(),
        accounts,
        data,
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let rpc = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    );

    // Load payer keypair
    let payer = read_keypair_file(
        std::env::var("HOME").unwrap() + "/.config/solana/id.json"
    ).expect("Failed to read keypair");
    let payer_pk = payer.pubkey();

    println!("=== Veil Transfer Hook — Devnet Demo ===\n");
    println!("Program:  {}", PROGRAM_ID);
    println!("Payer:    {}\n", payer_pk);

    // ── Step 1: Create Token-2022 Mint with Transfer Hook ───────────────
    println!("--- Step 1: Create Token-2022 Mint with Transfer Hook ---");

    let mint_kp = Keypair::new();
    let mint = mint_kp.pubkey();
    println!("Mint:     {}", mint);

    // Use spl-token CLI approach: create mint with transfer-hook extension
    // We need to build the raw instructions for creating a mint with TransferHook extension
    let extensions = vec![spl_token_2022::extension::ExtensionType::TransferHook];
    let space = spl_token_2022::extension::ExtensionType::try_calculate_account_len::<spl_token_2022::state::Mint>(
        &extensions
    ).unwrap();

    let rent = rpc.get_minimum_balance_for_rent_exemption(space).unwrap();

    let create_mint_account_ix = system_instruction::create_account(
        &payer_pk,
        &mint,
        rent,
        space as u64,
        &token_2022(),
    );

    // Initialize TransferHook extension
    let init_hook_ix = spl_token_2022::extension::transfer_hook::instruction::initialize(
        &token_2022(),
        &mint,
        Some(payer_pk),  // authority
        Some(program_id()),  // transfer hook program
    ).unwrap();

    // Initialize Mint
    let init_mint_ix = spl_token_2022::instruction::initialize_mint(
        &token_2022(),
        &mint,
        &payer_pk, // mint authority
        None,      // freeze authority
        6,         // decimals
    ).unwrap();

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_mint_account_ix, init_hook_ix, init_mint_ix],
        Some(&payer_pk),
        &[&payer, &mint_kp],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Mint created: {}", solscan(&sig.to_string()));

    // ── Step 2: Initialize ExtraAccountMetas ────────────────────────────
    println!("\n--- Step 2: Initialize ExtraAccountMetas ---");

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_init_extra_metas(&payer_pk, &mint);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  ExtraAccountMetas initialized: {}", solscan(&sig.to_string()));

    // ── Step 3: Create Policy (with caps) ───────────────────────────────
    println!("\n--- Step 3: Create Policy ---");
    println!("  tx_cap=1_000_000, daily_cap=5_000_000, monthly_cap=50_000_000");
    println!("  velocity=5 tx/60s, time window=0-24 (always open), mode=open");

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_create_policy(
        &payer_pk,
        &mint,
        1_000_000,    // tx cap: 1 token (6 decimals)
        5_000_000,    // daily cap: 5 tokens
        50_000_000,   // monthly cap: 50 tokens
        5,            // velocity max: 5 transfers
        60,           // velocity window: 60 seconds
        0,            // time start: 0 UTC
        0,            // time end: 0 UTC (0/0 = always allowed)
        2,            // mode: open (no whitelist)
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), payer_pk.as_ref()]);
    let (tracker_pda, _) = derive_pda(&[TRACKER_SEED, mint.as_ref(), payer_pk.as_ref()]);
    println!("  Policy PDA:  {}", policy_pda);
    println!("  Tracker PDA: {}", tracker_pda);
    println!("  Policy created: {}", solscan(&sig.to_string()));

    // ── Step 4: Mint tokens to owner ────────────────────────────────────
    println!("\n--- Step 4: Mint tokens to owner ---");

    let owner_ata = get_associated_token_address_with_program_id(
        &payer_pk, &mint, &token_2022()
    );
    let create_ata_ix = create_associated_token_account(
        &payer_pk, &payer_pk, &mint, &token_2022()
    );

    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &token_2022(),
        &mint,
        &owner_ata,
        &payer_pk,
        &[],
        100_000_000, // 100 tokens
    ).unwrap();

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix, mint_to_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Owner ATA: {}", owner_ata);
    println!("  Minted 100 tokens: {}", solscan(&sig.to_string()));

    // ── Step 5: Create destination wallet + ATA ─────────────────────────
    println!("\n--- Step 5: Create destination wallet ---");

    let dest_kp = Keypair::new();
    let dest = dest_kp.pubkey();
    let dest_ata = get_associated_token_address_with_program_id(
        &dest, &mint, &token_2022()
    );

    let create_dest_ata_ix = create_associated_token_account(
        &payer_pk, &dest, &mint, &token_2022()
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_dest_ata_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Destination:     {}", dest);
    println!("  Destination ATA: {}", dest_ata);
    println!("  ATA created: {}", solscan(&sig.to_string()));

    // ── Step 6: Transfer (should succeed — within caps) ─────────────────
    println!("\n--- Step 6: Transfer 0.5 tokens (within tx_cap=1) ---");

    let transfer_ix = ix_transfer_checked_with_hook(
        &owner_ata, &mint, &dest_ata, &payer_pk,
        500_000, // 0.5 tokens
        6,
        &payer_pk,
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  Transfer succeeded: {}", solscan(&sig.to_string())),
        Err(e) => println!("  Transfer result: {}", e),
    }

    // ── Step 7: Transfer exceeding tx_cap (should fail) ─────────────────
    println!("\n--- Step 7: Transfer 2 tokens (exceeds tx_cap=1, should FAIL) ---");

    let transfer_ix = ix_transfer_checked_with_hook(
        &owner_ata, &mint, &dest_ata, &payer_pk,
        2_000_000, // 2 tokens > tx_cap of 1
        6,
        &payer_pk,
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  Transfer succeeded (unexpected): {}", solscan(&sig.to_string())),
        Err(e) => println!("  Transfer correctly rejected: {}", e),
    }

    // ── Step 8: UpdatePolicy — lower daily cap ──────────────────────────
    println!("\n--- Step 8: UpdatePolicy — set daily_cap to 1 token ---");

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_update_policy(
        &payer_pk, &mint,
        1_000_000,   // tx cap stays at 1
        1_000_000,   // daily cap: 1 token (we already spent 0.5, so 0.5 left)
        50_000_000,
        5, 60,
        0, 0,
        2, // mode still open
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Policy updated: {}", solscan(&sig.to_string()));

    // ── Step 9: Transfer that exceeds daily cap ─────────────────────────
    println!("\n--- Step 9: Transfer 0.8 tokens (0.5 + 0.8 > daily_cap=1, should FAIL) ---");

    let transfer_ix = ix_transfer_checked_with_hook(
        &owner_ata, &mint, &dest_ata, &payer_pk,
        800_000,
        6,
        &payer_pk,
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  Transfer succeeded (unexpected): {}", solscan(&sig.to_string())),
        Err(e) => println!("  Transfer correctly rejected (daily cap): {}", e),
    }

    // ── Step 10: Add Delegation ─────────────────────────────────────────
    println!("\n--- Step 10: Add Delegation ---");

    let delegate_kp = Keypair::new();
    let delegate = delegate_kp.pubkey();
    println!("  Delegate: {}", delegate);

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_add_delegation(
        &payer_pk, &mint,
        &delegate,
        2_000_000, // delegate daily cap: 2 tokens
        500_000,   // delegate tx cap: 0.5 tokens
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Delegation added: {}", solscan(&sig.to_string()));

    // ── Step 11: Whitelist mode — set root and approve destination ───────
    println!("\n--- Step 11: Set whitelist root + approve destination ---");

    // Build a 2-leaf Merkle tree with dest_ata and a dummy address
    let dummy_addr = Pubkey::new_unique();
    let (root, proof_dest, _proof_dummy) = build_merkle_2(
        dest_ata.as_ref().try_into().unwrap(),
        dummy_addr.as_ref().try_into().unwrap(),
    );

    // First update policy to whitelist mode
    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_update_policy(
        &payer_pk, &mint,
        1_000_000, 5_000_000, 50_000_000, // restore daily cap
        5, 60, 0, 0,
        0, // mode = whitelist
    );
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Mode set to whitelist: {}", solscan(&sig.to_string()));

    // Set the Merkle root
    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_set_whitelist_root(&payer_pk, &mint, &root);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Whitelist root set: {}", solscan(&sig.to_string()));

    // Approve destination with Merkle proof
    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_approve_destination(&payer_pk, &mint, &dest_ata, &proof_dest);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    let (approval_pda, _) = derive_pda(&[APPROVAL_SEED, mint.as_ref(), payer_pk.as_ref(), dest_ata.as_ref()]);
    println!("  Approval PDA: {}", approval_pda);
    println!("  Destination approved: {}", solscan(&sig.to_string()));

    // ── Step 12: Transfer with whitelist (should succeed) ───────────────
    println!("\n--- Step 12: Transfer with whitelist approval (should succeed) ---");

    let transfer_ix = ix_transfer_checked_with_hook(
        &owner_ata, &mint, &dest_ata, &payer_pk,
        100_000, // 0.1 tokens
        6,
        &payer_pk,
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  Whitelisted transfer succeeded: {}", solscan(&sig.to_string())),
        Err(e) => println!("  Transfer result: {}", e),
    }

    // ── Step 13: Revoke approval ────────────────────────────────────────
    println!("\n--- Step 13: Revoke approval ---");

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = ix_revoke_approval(&payer_pk, &mint, &dest_ata);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Approval revoked: {}", solscan(&sig.to_string()));

    // ── Step 14: Transfer after revocation (should fail — not whitelisted) ──
    println!("\n--- Step 14: Transfer after revocation (should FAIL) ---");

    let transfer_ix = ix_transfer_checked_with_hook(
        &owner_ata, &mint, &dest_ata, &payer_pk,
        100_000,
        6,
        &payer_pk,
    );

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&payer_pk),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  Transfer succeeded (unexpected): {}", solscan(&sig.to_string())),
        Err(e) => println!("  Transfer correctly rejected (revoked): {}", e),
    }

    println!("\n=== Demo Complete ===");
    println!("\nAll PDAs:");
    let (em_pda, _) = derive_pda(&[EXTRA_METAS_SEED, mint.as_ref()]);
    println!("  ExtraAccountMetas: https://solscan.io/account/{}?cluster=devnet", em_pda);
    println!("  Policy:            https://solscan.io/account/{}?cluster=devnet", policy_pda);
    println!("  Tracker:           https://solscan.io/account/{}?cluster=devnet", tracker_pda);
    println!("  Mint:              https://solscan.io/account/{}?cluster=devnet", mint);
}
