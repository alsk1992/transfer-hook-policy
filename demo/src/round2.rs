///! Veil Transfer Hook — Devnet Demo Round 2
///!
///! Proves the remaining features: velocity limit, time-of-day window,
///! delegate transfer, monthly cap, and stale approval after root rotation.

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
use spl_associated_token_account::{
    get_associated_token_address_with_program_id,
    instruction::create_associated_token_account,
};
use std::str::FromStr;

// ── Constants ───────────────────────────────────────────────────────────────

const PROGRAM_ID: &str = "J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

const POLICY_SEED: &[u8] = b"policy";
const TRACKER_SEED: &[u8] = b"tracker";
const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";
const APPROVAL_SEED: &[u8] = b"approval";

const INIT_EXTRA_DISC: [u8; 8] = [43, 34, 13, 49, 167, 88, 235, 235];

const CREATE_POLICY: u8 = 0x00;
const UPDATE_POLICY: u8 = 0x01;
const ADD_DELEGATION: u8 = 0x02;
const SET_WHITELIST_ROOT: u8 = 0x03;
const APPROVE_DESTINATION: u8 = 0x04;

fn program_id() -> Pubkey { Pubkey::from_str(PROGRAM_ID).unwrap() }
fn token_2022() -> Pubkey { Pubkey::from_str(TOKEN_2022).unwrap() }

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

fn build_merkle_2(leaf0: &[u8; 32], leaf1: &[u8; 32]) -> ([u8; 32], Vec<(u8, [u8; 32])>, Vec<(u8, [u8; 32])>) {
    let h0 = sha256(leaf0);
    let h1 = sha256(leaf1);
    let mut combined = [0u8; 64];
    if h0 <= h1 {
        combined[..32].copy_from_slice(&h0);
        combined[32..].copy_from_slice(&h1);
        let root = sha256(&combined);
        (root, vec![(0, h1)], vec![(1, h0)])
    } else {
        combined[..32].copy_from_slice(&h1);
        combined[32..].copy_from_slice(&h0);
        let root = sha256(&combined);
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
    owner: &Pubkey, mint: &Pubkey,
    tx_cap: u64, daily_cap: u64, monthly_cap: u64,
    velocity_max: u16, velocity_window: u16,
    time_start: u8, time_end: u8, mode: u8,
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
    owner: &Pubkey, mint: &Pubkey,
    tx_cap: u64, daily_cap: u64, monthly_cap: u64,
    velocity_max: u16, velocity_window: u16,
    time_start: u8, time_end: u8, mode: u8,
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
    owner: &Pubkey, mint: &Pubkey, delegate: &Pubkey,
    daily_cap: u64, tx_cap: u64,
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

fn ix_set_whitelist_root(owner: &Pubkey, mint: &Pubkey, root: &[u8; 32]) -> Instruction {
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
    owner: &Pubkey, mint: &Pubkey, destination: &Pubkey,
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

fn ix_transfer_checked_with_hook(
    source_ata: &Pubkey, mint: &Pubkey, dest_ata: &Pubkey,
    authority: &Pubkey, amount: u64, decimals: u8,
    token_owner: &Pubkey,
) -> Instruction {
    let (extra_metas_pda, _) = derive_pda(&[EXTRA_METAS_SEED, mint.as_ref()]);
    let (policy_pda, _) = derive_pda(&[POLICY_SEED, mint.as_ref(), token_owner.as_ref()]);
    let (tracker_pda, _) = derive_pda(&[TRACKER_SEED, mint.as_ref(), token_owner.as_ref()]);
    let (approval_pda, _) = derive_pda(&[APPROVAL_SEED, mint.as_ref(), token_owner.as_ref(), dest_ata.as_ref()]);

    let mut data = vec![12]; // TransferChecked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    Instruction {
        program_id: token_2022(),
        accounts: vec![
            AccountMeta::new(*source_ata, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*dest_ata, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(extra_metas_pda, false),
            AccountMeta::new_readonly(policy_pda, false),
            AccountMeta::new(tracker_pda, false),
            AccountMeta::new_readonly(approval_pda, false),
            AccountMeta::new_readonly(program_id(), false),
        ],
        data,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn create_mint_with_hook(rpc: &RpcClient, payer: &Keypair) -> (Keypair, Pubkey) {
    let mint_kp = Keypair::new();
    let mint = mint_kp.pubkey();

    let extensions = vec![spl_token_2022::extension::ExtensionType::TransferHook];
    let space = spl_token_2022::extension::ExtensionType::try_calculate_account_len::<spl_token_2022::state::Mint>(
        &extensions
    ).unwrap();
    let rent = rpc.get_minimum_balance_for_rent_exemption(space).unwrap();

    let create_ix = system_instruction::create_account(
        &payer.pubkey(), &mint, rent, space as u64, &token_2022(),
    );
    let hook_ix = spl_token_2022::extension::transfer_hook::instruction::initialize(
        &token_2022(), &mint, Some(payer.pubkey()), Some(program_id()),
    ).unwrap();
    let init_ix = spl_token_2022::instruction::initialize_mint(
        &token_2022(), &mint, &payer.pubkey(), None, 6,
    ).unwrap();

    let blockhash = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ix, hook_ix, init_ix],
        Some(&payer.pubkey()),
        &[payer, &mint_kp],
        blockhash,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Mint {} created: {}", mint, solscan(&sig.to_string()));

    (mint_kp, mint)
}

fn setup_full(
    rpc: &RpcClient, payer: &Keypair, mint: &Pubkey,
    tx_cap: u64, daily_cap: u64, monthly_cap: u64,
    vel_max: u16, vel_win: u16,
    time_start: u8, time_end: u8, mode: u8,
) -> (Pubkey, Pubkey) {
    let pk = payer.pubkey();

    // Init extra metas
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ix_init_extra_metas(&pk, mint)], Some(&pk), &[payer], bh,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  ExtraAccountMetas: {}", solscan(&sig.to_string()));

    // Create policy
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ix_create_policy(&pk, mint, tx_cap, daily_cap, monthly_cap, vel_max, vel_win, time_start, time_end, mode)],
        Some(&pk), &[payer], bh,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Policy created: {}", solscan(&sig.to_string()));

    // Create owner ATA + mint tokens
    let owner_ata = get_associated_token_address_with_program_id(&pk, mint, &token_2022());
    let create_ata = create_associated_token_account(&pk, &pk, mint, &token_2022());
    let mint_to = spl_token_2022::instruction::mint_to(
        &token_2022(), mint, &owner_ata, &pk, &[], 100_000_000,
    ).unwrap();
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ata, mint_to], Some(&pk), &[payer], bh,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Minted 100 tokens: {}", solscan(&sig.to_string()));

    // Create dest ATA
    let dest_kp = Keypair::new();
    let dest = dest_kp.pubkey();
    let dest_ata = get_associated_token_address_with_program_id(&dest, mint, &token_2022());
    let create_dest = create_associated_token_account(&pk, &dest, mint, &token_2022());
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_dest], Some(&pk), &[payer], bh,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Dest ATA {}: {}", dest_ata, solscan(&sig.to_string()));

    (owner_ata, dest_ata)
}

fn do_transfer(rpc: &RpcClient, payer: &Keypair, signers: &[&Keypair],
               owner_ata: &Pubkey, mint: &Pubkey, dest_ata: &Pubkey,
               authority: &Pubkey, amount: u64, token_owner: &Pubkey, label: &str) {
    let ix = ix_transfer_checked_with_hook(
        owner_ata, mint, dest_ata, authority, amount, 6, token_owner,
    );
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[ix], Some(&payer.pubkey()), signers, bh,
    );
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("  {} SUCCESS: {}", label, solscan(&sig.to_string())),
        Err(e) => {
            let err_str = e.to_string();
            // Extract the error code
            if let Some(pos) = err_str.find("0x") {
                let code = &err_str[pos..pos+6];
                println!("  {} REJECTED ({}): {}", label, code, solscan_from_err(&err_str));
            } else {
                println!("  {} REJECTED: {}", label, err_str);
            }
        }
    }
}

fn solscan_from_err(err: &str) -> String {
    // Failed txs don't land on-chain, so no solscan link — just show the error
    format!("[simulated — {}]", if err.len() > 120 { &err[..120] } else { err })
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let rpc = RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    );

    let payer = read_keypair_file(
        std::env::var("HOME").unwrap() + "/.config/solana/id.json"
    ).expect("Failed to read keypair");
    let pk = payer.pubkey();

    println!("=== Veil Transfer Hook — Devnet Demo Round 2 ===\n");
    println!("Program: {}", PROGRAM_ID);
    println!("Payer:   {}\n", pk);

    // ════════════════════════════════════════════════════════════════════════
    //  TEST A: Velocity Limit
    // ════════════════════════════════════════════════════════════════════════
    println!("━━━ TEST A: Velocity Limit (max 2 transfers per 300s) ━━━\n");

    let (_, mint_a) = create_mint_with_hook(&rpc, &payer);
    let (ata_a, dest_a) = setup_full(
        &rpc, &payer, &mint_a,
        0,          // no tx cap
        0,          // no daily cap
        0,          // no monthly cap
        2, 300,     // velocity: max 2 per 300s
        0, 0,       // no time restriction
        2,          // mode: open
    );

    println!();
    do_transfer(&rpc, &payer, &[&payer], &ata_a, &mint_a, &dest_a, &pk, 10_000, &pk, "Transfer 1/2");
    do_transfer(&rpc, &payer, &[&payer], &ata_a, &mint_a, &dest_a, &pk, 10_000, &pk, "Transfer 2/2");
    do_transfer(&rpc, &payer, &[&payer], &ata_a, &mint_a, &dest_a, &pk, 10_000, &pk, "Transfer 3/2 (should FAIL 0x5604)");

    // ════════════════════════════════════════════════════════════════════════
    //  TEST B: Time-of-Day Window Rejection
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━━ TEST B: Time-of-Day Window Rejection ━━━\n");

    // Get current UTC hour, then set a window that excludes it
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_secs() as i64;
    let current_hour = ((now % 86400) / 3600) as u8;
    // Set window 2 hours ahead of now → current hour is outside
    let window_start = (current_hour + 2) % 24;
    let window_end = (current_hour + 4) % 24;
    println!("  Current UTC hour: {}", current_hour);
    println!("  Setting allowed window: {}:00 - {}:00 UTC (excludes now)", window_start, window_end);

    let (_, mint_b) = create_mint_with_hook(&rpc, &payer);
    let (ata_b, dest_b) = setup_full(
        &rpc, &payer, &mint_b,
        0, 0, 0,    // no caps
        0, 0,        // no velocity
        window_start, window_end, // time window excluding current hour
        2,           // mode: open
    );

    println!();
    do_transfer(&rpc, &payer, &[&payer], &ata_b, &mint_b, &dest_b, &pk, 10_000, &pk,
                "Transfer outside time window (should FAIL 0x5605)");

    // Now update to a window that includes current hour
    let good_start = current_hour;
    let good_end = (current_hour + 6) % 24;
    println!("\n  Updating window to {}:00 - {}:00 UTC (includes now)", good_start, good_end);
    let bh = rpc.get_latest_blockhash().unwrap();
    let ix = ix_update_policy(&pk, &mint_b, 0, 0, 0, 0, 0, good_start, good_end, 2);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Policy updated: {}", solscan(&sig.to_string()));

    do_transfer(&rpc, &payer, &[&payer], &ata_b, &mint_b, &dest_b, &pk, 10_000, &pk,
                "Transfer within time window (should SUCCEED)");

    // ════════════════════════════════════════════════════════════════════════
    //  TEST C: Monthly Cap
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━━ TEST C: Monthly Cap ━━━\n");

    let (_, mint_c) = create_mint_with_hook(&rpc, &payer);
    let (ata_c, dest_c) = setup_full(
        &rpc, &payer, &mint_c,
        0,            // no tx cap
        0,            // no daily cap
        500_000,      // monthly cap: 0.5 tokens
        0, 0,         // no velocity
        0, 0,         // no time restriction
        2,            // mode: open
    );

    println!();
    do_transfer(&rpc, &payer, &[&payer], &ata_c, &mint_c, &dest_c, &pk, 300_000, &pk,
                "Transfer 0.3 tokens (within monthly cap 0.5)");
    do_transfer(&rpc, &payer, &[&payer], &ata_c, &mint_c, &dest_c, &pk, 300_000, &pk,
                "Transfer 0.3 tokens (0.3+0.3=0.6 > 0.5, should FAIL 0x5603)");

    // ════════════════════════════════════════════════════════════════════════
    //  TEST D: Delegate Transfer
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━━ TEST D: Delegate Transfer ━━━\n");

    let (_, mint_d) = create_mint_with_hook(&rpc, &payer);
    let (ata_d, dest_d) = setup_full(
        &rpc, &payer, &mint_d,
        0, 0, 0,      // no global caps
        0, 0,          // no velocity
        0, 0,          // no time restriction
        2,             // mode: open
    );

    let delegate_kp = Keypair::new();
    let delegate = delegate_kp.pubkey();
    println!("  Delegate: {}", delegate);

    // Fund delegate (needs SOL for... actually payer pays fees)
    // Add delegation to policy
    let bh = rpc.get_latest_blockhash().unwrap();
    let ix = ix_add_delegation(&pk, &mint_d, &delegate, 1_000_000, 500_000);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Delegation added (daily=1, tx=0.5): {}", solscan(&sig.to_string()));

    // Approve delegate on the Token-2022 token account
    let approve_ix = spl_token_2022::instruction::approve(
        &token_2022(),
        &ata_d,           // source token account
        &delegate,        // delegate
        &pk,              // owner
        &[],
        50_000_000,       // approve 50 tokens
    ).unwrap();
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(&[approve_ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Token-2022 delegate approved: {}", solscan(&sig.to_string()));

    // Delegate transfers (payer pays fee, delegate is authority)
    println!();
    do_transfer(&rpc, &payer, &[&payer, &delegate_kp], &ata_d, &mint_d, &dest_d,
                &delegate, 100_000, &pk, "Delegate transfer 0.1 tokens (within sub-cap)");

    // Delegate exceeds per-tx sub-cap (0.5 tokens)
    do_transfer(&rpc, &payer, &[&payer, &delegate_kp], &ata_d, &mint_d, &dest_d,
                &delegate, 600_000, &pk, "Delegate transfer 0.6 tokens (exceeds delegate tx_cap=0.5, should FAIL 0x5601)");

    // ════════════════════════════════════════════════════════════════════════
    //  TEST E: Stale Approval After Root Rotation
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━━ TEST E: Stale Approval After Root Rotation ━━━\n");

    let (_, mint_e) = create_mint_with_hook(&rpc, &payer);
    let (ata_e, dest_e) = setup_full(
        &rpc, &payer, &mint_e,
        0, 0, 0, 0, 0, 0, 0,
        0, // whitelist mode
    );

    // Build Merkle tree and set root
    let dummy = Pubkey::new_unique();
    let (root1, proof1, _) = build_merkle_2(
        dest_e.as_ref().try_into().unwrap(),
        dummy.as_ref().try_into().unwrap(),
    );

    let bh = rpc.get_latest_blockhash().unwrap();
    let ix = ix_set_whitelist_root(&pk, &mint_e, &root1);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Root 1 set: {}", solscan(&sig.to_string()));

    // Approve destination
    let bh = rpc.get_latest_blockhash().unwrap();
    let ix = ix_approve_destination(&pk, &mint_e, &dest_e, &proof1);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Destination approved under root 1: {}", solscan(&sig.to_string()));

    // Transfer should work
    do_transfer(&rpc, &payer, &[&payer], &ata_e, &mint_e, &dest_e, &pk, 10_000, &pk,
                "Transfer with valid approval");

    // Now rotate root to a completely different tree
    let dummy2 = Pubkey::new_unique();
    let dummy3 = Pubkey::new_unique();
    let (root2, _, _) = build_merkle_2(
        dummy2.as_ref().try_into().unwrap(),
        dummy3.as_ref().try_into().unwrap(),
    );

    let bh = rpc.get_latest_blockhash().unwrap();
    let ix = ix_set_whitelist_root(&pk, &mint_e, &root2);
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&pk), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).unwrap();
    println!("  Root rotated to root 2: {}", solscan(&sig.to_string()));

    // Transfer should fail — approval has root1 but policy now has root2
    do_transfer(&rpc, &payer, &[&payer], &ata_e, &mint_e, &dest_e, &pk, 10_000, &pk,
                "Transfer with stale approval (should FAIL 0x5600)");

    println!("\n=== Round 2 Complete ===");
}
