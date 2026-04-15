# Veil — Programmable Spending Policies for Token-2022

**Rules follow the money — not the wallet.**

Veil is an open-source [Transfer Hook](https://spl.solana.com/token-2022/extensions#transfer-hook) for Solana's Token-2022 that enforces spending policies at the *token* level. Attach caps, velocity limits, time windows, and delegation controls to any SPL token — enforced on every transfer, with no way to bypass.

Built from scratch in [Pinocchio](https://github.com/anza-xyz/pinocchio). Zero Anchor. Zero alloc in the hot path. Zero-copy state. **~3,500 CU per transfer.**

## What It Enforces

| Rule | Description |
|------|-------------|
| **Per-tx cap** | Reject any single transfer above a threshold |
| **Daily cap** | Rolling 24h cumulative spend limit with auto-reset |
| **Monthly cap** | Rolling 30-day cumulative spend limit with auto-reset |
| **Velocity limit** | Max N transfers per configurable time window |
| **Time-of-day window** | Restrict transfers to specific UTC hours (e.g. business hours only) |
| **Recipient whitelist** | Merkle-root-based recipient allow-list (ZK verification planned) |
| **Delegated spending** | Grant sub-limited authority to other wallets or agents — with their own caps |

## Why This Exists

Smart contract wallets are great, but they protect the *wallet* — not the *money*. The moment tokens leave a guarded wallet, all restrictions vanish.

Veil flips this: policies are attached to the **token mint** via Token-2022's transfer hook. Every transfer is intercepted and checked against the owner's policy before it can proceed. You can delegate spending authority to an AI agent, a payments bot, or an employee wallet — and the tokens themselves enforce the limits.

**Use cases:**
- **Corporate treasury** — enforce spending policies on stablecoin disbursements
- **AI agent wallets** — give agents spending authority with hard caps they can't exceed
- **Parental controls** — limit how much/when/where a child's token account can send
- **Payroll rails** — time-locked, rate-limited token distributions
- **DAO operations** — delegate scoped spending to multisig signers

## Architecture

```
 Token-2022 transfer
       │
       ▼
 ┌──────────────────┐  resolves   ┌───────────────────┐
 │ ExtraAccountMeta  │────────────▶│  Policy PDA (ro)  │
 │       List        │             │  Tracker PDA (rw) │
 └────────┬─────────┘             └───────────────────┘
          │
          ▼
 ┌──────────────────┐  enforces   ┌───────────────────┐
 │  Execute handler  │────────────▶│  tx cap           │
 │                   │             │  daily/monthly    │
 │  ~3,500 CU        │             │  velocity         │
 │  (zero alloc)     │             │  time window      │
 └──────────────────┘             │  delegations      │
                                   └───────────────────┘
```

**PDAs are derived from the token account owner** (read from source account data), not the transfer authority. This is what makes delegation work — a delegate can transfer on behalf of the owner, and the hook still finds the owner's policy.

## Instructions

| Disc | Name | Description |
|------|------|-------------|
| `8B` | `Execute` | Transfer hook entry — enforces all spending rules |
| `8B` | `InitializeExtraAccountMetas` | One-time setup — registers PDAs with the runtime |
| `0x00` | `CreatePolicy` | Create a policy + tracker for a (mint, owner) pair |
| `0x01` | `UpdatePolicy` | Modify policy rules (owner only) |
| `0x02` | `AddDelegation` | Grant sub-limited spend authority to another wallet |

## State Layout

**Policy PDA** — `["policy", mint, owner]` — 240 bytes
```
 0:   discriminator (8B)    40:  mint (32B)
 8:   owner (32B)           72:  tx_cap, daily_cap, monthly_cap (24B)
 96:  velocity_max/window   100: time_start/end_h
 102: mode                  104: whitelist_root (32B)
 136: delegations_len       138: 2× DelegationSlot (96B)
```

**Tracker PDA** — `["tracker", mint, owner]` — 64 bytes
```
 0:   discriminator (8B)    8:  daily_spent (8B)
 16:  monthly_spent (8B)    24: daily_reset_ts (8B)
 32:  monthly_reset_ts (8B) 40: velocity_count (2B)
 42:  velocity_window_start  50: tx_count_total (8B)
```

## Building

```bash
# Build the SBF binary
cargo build-sbf

# Run integration tests (27 tests)
cargo test --test integration
```

Requires:
- Rust + Solana CLI toolchain (`cargo build-sbf`)
- The program compiles to `target/deploy/veil_hook.so`

## Deploying

```bash
# Generate a keypair (or use an existing one)
solana-keygen new -o veil-hook-keypair.json

# Update the program ID in src/lib.rs to match
# solana_address::declare_id!("YOUR_PROGRAM_ID");

# Deploy to devnet
solana program deploy target/deploy/veil_hook.so \
  --program-id veil-hook-keypair.json \
  --url devnet

# Create a Token-2022 mint with transfer hook
spl-token create-token \
  --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb \
  --transfer-hook YOUR_PROGRAM_ID

# Initialize extra account metas for the mint
# (call InitializeExtraAccountMetas instruction)

# Create a policy for the token owner
# (call CreatePolicy with desired caps)
```

## Design Decisions

- **Pinocchio over Anchor** — Anchor's deserialization overhead is ~5-10x more CU. Pinocchio gives us direct account data access for minimal compute cost.
- **Zero-copy state** — All reads/writes go directly to account data slices. No alloc, no serde, no intermediate structs.
- **Owner-keyed PDAs** — Policy and tracker PDAs use the token account owner (read from source account data via `AccountData` seed resolution), not the transfer authority. This is what makes delegation composable.
- **Shared tracker** — Owner and delegates share a single tracker. Delegate sub-caps act as additional restrictions on top of global caps (`min(delegate_cap, global_cap)`).
- **Mode validation** — Only `0` (whitelist), `1` (blacklist), `2` (open) are accepted. Invalid modes are rejected at creation.
- **Whitelist security default** — Whitelist mode with a non-zero Merkle root rejects all transfers until ZK proof verification is implemented. This is the safe default.

## Test Coverage

27 integration tests via [mollusk-svm](https://github.com/anza-xyz/agave/tree/master/mollusk-svm):

- **CreatePolicy** — success, already-initialized, missing signer, invalid mode
- **UpdatePolicy** — success, wrong owner rejection
- **AddDelegation** — success with cap verification
- **Execute** — basic transfer, all cap types, velocity limits, time windows, daily/monthly resets, cumulative tracking, boundary conditions, zero-caps-as-unlimited
- **Delegation** — successful delegate transfer, delegate tx cap enforcement, unauthorized wallet rejection
- **Whitelist** — rejection with non-zero root, passthrough with zero root
- **InitExtraAccountMetas** — TLV encoding verification, already-initialized guard

## Roadmap

- [ ] ZK proof verification for whitelist mode (Groth16 Merkle membership)
- [ ] Blacklist mode with on-chain recipient list
- [ ] Per-delegate spend tracking (separate counters)
- [ ] `RemoveDelegation` instruction
- [ ] Client SDK (TypeScript)
- [ ] Devnet deployment + example scripts

## License

MIT
