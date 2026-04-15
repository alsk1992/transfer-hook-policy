# transfer-hook-policy

**Programmable spending policies for Solana Token-2022.**

An open-source [Transfer Hook](https://spl.solana.com/token-2022/extensions#transfer-hook) that enforces spending rules at the *token* level. Attach per-tx caps, daily/monthly limits, velocity controls, time-of-day windows, and scoped delegation to any Token-2022 mint — enforced on every transfer, impossible to bypass.

Built from scratch in [Pinocchio](https://github.com/anza-xyz/pinocchio). Zero Anchor. Zero alloc in the hot path. Zero-copy state. **~3,500 CU per transfer.**

---

## What It Enforces

| Rule | Description |
|------|-------------|
| **Per-tx cap** | Reject any single transfer above a threshold |
| **Daily cap** | Rolling 24h cumulative spend limit with auto-reset |
| **Monthly cap** | Rolling 30-day cumulative spend limit with auto-reset |
| **Velocity limit** | Max N transfers per configurable time window |
| **Time-of-day window** | Restrict transfers to specific UTC hours (e.g. business hours only) |
| **Recipient whitelist** | Merkle-root-based recipient allow-list (ZK proof verification planned) |
| **Delegated spending** | Grant sub-limited authority to other wallets or AI agents — with their own caps |

## Why

Smart contract wallets protect the *wallet* — not the *money*. The moment tokens leave, all restrictions vanish.

This hook flips that: policies are attached to the **token mint** via Token-2022's transfer hook extension. Every transfer is intercepted and checked against the owner's policy before it proceeds. Delegate spending to an AI agent, a bot, or an employee — the tokens enforce the limits.

**Use cases:**
- **Corporate treasury** — enforce spending policies on stablecoin disbursements
- **AI agent wallets** — give agents spending authority with hard caps they can't exceed
- **Parental controls** — limit how much / when / where a child's token account can send
- **Payroll rails** — time-locked, rate-limited token distributions
- **DAO operations** — delegate scoped spending to committee members

## Architecture

```
Token-2022 transfer
      │
      ▼
┌──────────────────┐  resolves   ┌───────────────────┐
│ ExtraAccountMeta  │───────────▶│  Policy PDA (ro)  │
│       List        │            │  Tracker PDA (rw) │
└────────┬─────────┘            └───────────────────┘
         │
         ▼
┌──────────────────┐  enforces   ┌───────────────────┐
│  Execute handler  │───────────▶│  per-tx cap       │
│                   │            │  daily / monthly  │
│  ~3,500 CU        │            │  velocity limit   │
│  (zero alloc)     │            │  time window      │
└──────────────────┘            │  delegation caps  │
                                 └───────────────────┘
```

PDAs are derived from the **token account owner** (read from source account data via `AccountData` seed resolution), not the transfer authority. This is what makes delegation work — a delegate transfers on behalf of the owner, and the hook still resolves the owner's policy.

## Instructions

| Discriminator | Name | Description |
|---------------|------|-------------|
| 8-byte SPL | `Execute` | Transfer hook — enforces all spending rules |
| 8-byte SPL | `InitializeExtraAccountMetas` | One-time setup — registers PDAs with the runtime |
| `0x00` | `CreatePolicy` | Create a policy + tracker for a (mint, owner) pair |
| `0x01` | `UpdatePolicy` | Modify policy rules (owner only) |
| `0x02` | `AddDelegation` | Grant sub-limited spend authority to another wallet |

## State

### Policy PDA — `["policy", mint, owner]` — 240 bytes

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Discriminator (`veilpol\0`) |
| 8 | 32 | Owner pubkey |
| 40 | 32 | Mint pubkey |
| 72 | 8 | `tx_cap` — max per single transfer (0 = unlimited) |
| 80 | 8 | `daily_cap` — max cumulative per 24h (0 = unlimited) |
| 88 | 8 | `monthly_cap` — max cumulative per 30d (0 = unlimited) |
| 96 | 2 | `velocity_max` — max transfers per window (0 = unlimited) |
| 98 | 2 | `velocity_window` — window in seconds |
| 100 | 1 | `time_start_h` — earliest UTC hour (0 = any) |
| 101 | 1 | `time_end_h` — latest UTC hour (0 = any) |
| 102 | 1 | `mode` — 0=whitelist, 1=blacklist, 2=open |
| 104 | 32 | `whitelist_root` — Poseidon Merkle root |
| 136 | 1 | `delegations_len` — active delegation count (max 2) |
| 138 | 96 | 2 × DelegationSlot (48B each: pubkey + daily_cap + tx_cap) |

### Tracker PDA — `["tracker", mint, owner]` — 64 bytes

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Discriminator (`veiltrk\0`) |
| 8 | 8 | `daily_spent` |
| 16 | 8 | `monthly_spent` |
| 24 | 8 | `daily_reset_ts` |
| 32 | 8 | `monthly_reset_ts` |
| 40 | 2 | `velocity_count` |
| 42 | 8 | `velocity_window_start` |
| 50 | 8 | `tx_count_total` |

## Build & Test

```bash
# Build the SBF binary
cargo build-sbf

# Run integration tests (27 tests, all passing)
cargo test --test integration
```

Requires Rust + Solana CLI toolchain (`cargo build-sbf`). Outputs `target/deploy/veil_hook.so`.

## Deploy

```bash
# 1. Generate a program keypair
solana-keygen new -o program-keypair.json

# 2. Get the program ID
solana-keygen pubkey program-keypair.json
# → Update declare_id!() in src/lib.rs, then rebuild

# 3. Deploy
solana program deploy target/deploy/veil_hook.so \
  --program-id program-keypair.json \
  --url devnet

# 4. Create a Token-2022 mint with this hook
spl-token create-token \
  --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb \
  --transfer-hook <PROGRAM_ID>

# 5. Initialize extra account metas (one-time per mint)
# Send an InitializeExtraAccountMetas instruction with accounts:
#   [extra_metas_pda (writable), mint, authority (signer), system_program]

# 6. Create a spending policy
# Send a CreatePolicy instruction (disc 0x00) with accounts:
#   [owner (signer), mint, policy_pda (writable), tracker_pda (writable), system_program]
# Data: tx_cap(u64) + daily_cap(u64) + monthly_cap(u64) + velocity_max(u16)
#       + velocity_window(u16) + time_start_h(u8) + time_end_h(u8) + mode(u8)
```

## Design Decisions

- **Pinocchio over Anchor** — Direct account data access, ~5-10x less CU than Anchor's deserialization overhead
- **Zero-copy state** — All reads/writes go directly to account data slices. No alloc, no serde, no intermediate structs
- **Owner-keyed PDAs** — PDAs use the token account owner (via `AccountData` seed resolution at index 0, offset 32), not the transfer authority. This makes delegation composable without separate PDA trees
- **Shared tracker** — Owner and delegates share one tracker. Delegate sub-caps are enforced as `min(delegate_cap, global_cap)` — delegates can never exceed global limits
- **Whitelist security default** — Whitelist mode with a non-zero Merkle root rejects all transfers until ZK verification is implemented. Fail-closed, not fail-open

## Test Coverage

27 integration tests via [mollusk-svm](https://crates.io/crates/mollusk-svm):

- **CreatePolicy** — success, already-initialized, missing signer, invalid mode
- **UpdatePolicy** — success, wrong owner rejection
- **AddDelegation** — success with cap verification
- **Execute** — basic transfer, all cap types (tx/daily/monthly), velocity limits + window reset, time-of-day windows, daily/monthly counter resets, cumulative tracking, exact boundary conditions, zero-caps-as-unlimited
- **Delegation** — successful delegate transfer, delegate tx cap enforcement, unauthorized wallet rejection
- **Whitelist** — rejection with non-zero root, passthrough with zero root
- **InitExtraAccountMetas** — full TLV + seed encoding verification, already-initialized guard

## Roadmap

- [ ] ZK proof verification for whitelist mode (Groth16 Merkle membership)
- [ ] Blacklist mode with on-chain recipient list
- [ ] Per-delegate spend tracking (separate counters)
- [ ] `RemoveDelegation` instruction
- [ ] TypeScript client SDK
- [ ] Devnet deployment + example scripts

## License

[MIT](LICENSE)
