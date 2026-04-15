//! Zero-copy state layouts for Veil PDAs.
//!
//! All accounts are fixed-size, packed, little-endian.  We read/write
//! directly from account data slices — no serde, no alloc.

// ── PDA Seeds ────────────────────────────────────────────────────────────────

pub const POLICY_SEED: &[u8] = b"policy";
pub const TRACKER_SEED: &[u8] = b"tracker";
pub const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";

// ── Policy PDA ───────────────────────────────────────────────────────────────
//
// Spending policy attached to a (mint, owner) pair.
//
// ```text
//   Offset  Size  Field
//   ──────  ────  ──────────────────────────────────────
//    0       8    discriminator   b"veilpol\0"
//    8      32    owner           pubkey — who can modify this policy
//   40      32    mint            pubkey — which token this governs
//   72       8    tx_cap          u64  max per single transfer   (0 = unlimited)
//   80       8    daily_cap       u64  max cumulative daily      (0 = unlimited)
//   88       8    monthly_cap     u64  max cumulative monthly    (0 = unlimited)
//   96       2    velocity_max    u16  max txs per window        (0 = unlimited)
//   98       2    velocity_window u16  window in seconds         (default 3600)
//  100       1    time_start_h    u8   earliest allowed hour UTC (0 = any)
//  101       1    time_end_h      u8   latest allowed hour UTC   (0 = any)
//  102       1    mode            u8   0=whitelist  1=blacklist  2=open
//  103       1    _pad
//  104      32    whitelist_root  Poseidon Merkle root of allowed recipients
//  136       1    delegations_len number of active delegation slots (max 2)
//  137       1    _pad2
//  138      96    delegations     2 × DelegationSlot (48 bytes each)
//  234       6    _reserved
//  ──────  ────
//  240           total
// ```

pub const POLICY_SIZE: usize = 240;
pub const POLICY_DISC: &[u8; 8] = b"veilpol\0";

pub mod policy {
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

// ── Delegation Slot ──────────────────────────────────────────────────────────
//
// ```text
//   Offset  Size  Field
//   ──────  ────  ─────────────────────────────
//    0      32    delegate   pubkey
//   32       8    daily_cap  u64  sub-limit
//   40       8    tx_cap     u64  per-tx sub-limit
//   ──────  ────
//   48            total
// ```

pub const DELEGATION_SLOT_SIZE: usize = 48;
pub const MAX_DELEGATIONS: usize = 2;

pub mod delegation {
    pub const DELEGATE: usize = 0;
    pub const DAILY_CAP: usize = 32;
    pub const TX_CAP: usize = 40;
}

// ── Spend Tracker PDA ────────────────────────────────────────────────────────
//
// Rolling spend counters for a (mint, owner) pair.
//
// ```text
//   Offset  Size  Field
//   ──────  ────  ──────────────────────────────────
//    0       8    discriminator          b"veiltrk\0"
//    8       8    daily_spent            u64
//   16       8    monthly_spent          u64
//   24       8    daily_reset_ts         i64  unix timestamp
//   32       8    monthly_reset_ts       i64  unix timestamp
//   40       2    velocity_count         u16  txs in current window
//   42       8    velocity_window_start  i64  when current window began
//   50       8    tx_count_total         u64  lifetime transfer count
//   58       6    _reserved
//   ──────  ────
//   64            total
// ```

pub const TRACKER_SIZE: usize = 64;
pub const TRACKER_DISC: &[u8; 8] = b"veiltrk\0";

pub mod tracker {
    pub const DISC: usize = 0;
    pub const DAILY_SPENT: usize = 8;
    pub const MONTHLY_SPENT: usize = 16;
    pub const DAILY_RESET_TS: usize = 24;
    pub const MONTHLY_RESET_TS: usize = 32;
    pub const VELOCITY_COUNT: usize = 40;
    pub const VELOCITY_WINDOW_START: usize = 42;
    pub const TX_COUNT_TOTAL: usize = 50;
}

// ── Time Constants ───────────────────────────────────────────────────────────

pub const SECONDS_PER_DAY: i64 = 86_400;
pub const SECONDS_PER_MONTH: i64 = 86_400 * 30;

// ── Byte Helpers ─────────────────────────────────────────────────────────────

#[inline(always)]
pub fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

#[inline(always)]
pub fn read_i64(data: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

#[inline(always)]
pub fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
}

#[inline(always)]
pub fn write_u64(data: &mut [u8], off: usize, val: u64) {
    data[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

#[inline(always)]
pub fn write_i64(data: &mut [u8], off: usize, val: i64) {
    data[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

#[inline(always)]
pub fn write_u16(data: &mut [u8], off: usize, val: u16) {
    data[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
