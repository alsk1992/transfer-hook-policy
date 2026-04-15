# Veil — Programmable Private Money on Solana

**Spending policies that follow the money — not the wallet.**

An open-source [Transfer Hook](https://spl.solana.com/token-2022/extensions#transfer-hook) that enforces spending rules at the *token* level. Attach per-tx caps, daily/monthly limits, velocity controls, time-of-day windows, SHA256 Merkle whitelists, and scoped delegation to any Token-2022 mint — enforced on every transfer, impossible to bypass.

Built from scratch in [Pinocchio](https://github.com/anza-xyz/pinocchio). Zero Anchor. Zero alloc in the hot path. Zero-copy state. **~3,500 CU per transfer.**

> **Live on Devnet** — [See proof below](#devnet-proof)

---

## What It Enforces

| Rule | Description |
|------|-------------|
| **Per-tx cap** | Reject any single transfer above a threshold |
| **Daily cap** | Rolling 24h cumulative spend limit with auto-reset |
| **Monthly cap** | Rolling 30-day cumulative spend limit with auto-reset |
| **Velocity limit** | Max N transfers per configurable time window |
| **Time-of-day window** | Restrict transfers to specific UTC hours (e.g. business hours only) |
| **Recipient whitelist** | SHA256 Merkle proof → on-chain approval PDA pattern. Only pre-approved destinations can receive |
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
┌──────────────────┐  resolves   ┌────────────────────┐
│ ExtraAccountMeta  │───────────▶│  Policy PDA (ro)   │
│       List        │            │  Tracker PDA (rw)  │
└────────┬─────────┘            │  Approval PDA (ro) │
         │                       └────────────────────┘
         ▼
┌──────────────────┐  enforces   ┌────────────────────┐
│  Execute handler  │───────────▶│  per-tx cap        │
│                   │            │  daily / monthly   │
│  ~3,500 CU        │            │  velocity limit    │
│  (zero alloc)     │            │  time window       │
└──────────────────┘            │  whitelist check   │
                                 │  delegation caps   │
                                 └────────────────────┘
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
| `0x03` | `SetWhitelistRoot` | Set/update SHA256 Merkle root on a policy |
| `0x04` | `ApproveDestination` | Verify Merkle proof and create on-chain approval PDA |
| `0x05` | `RevokeApproval` | Close an approval PDA (reclaim rent) |

## Whitelist Design

The whitelist uses a **SHA256 Merkle proof → approval PDA** pattern:

1. **Owner** builds a Merkle tree of approved destination addresses off-chain
2. **`SetWhitelistRoot`** stores the SHA256 root on the policy PDA
3. **`ApproveDestination`** takes a Merkle proof, verifies it on-chain via `sol_sha256` syscall (~100 CU/hash), and creates a persistent **Approval PDA** `["approval", mint, owner, destination]`
4. **`Execute`** (hot path) only checks if the Approval PDA exists and its root matches the current policy root — no proof verification per transfer

Root rotation auto-invalidates all existing approvals. Re-running `ApproveDestination` with new proofs updates the stored root. `RevokeApproval` closes the PDA and reclaims rent.

This keeps the hot path fast (~1,500 CU overhead for whitelist checks) while supporting trees of up to 2^20 (~1M) approved destinations.

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
| 104 | 32 | `whitelist_root` — SHA256 Merkle root |
| 136 | 1 | `delegations_len` — active delegation count (max 2) |
| 138 | 96 | 2 x DelegationSlot (48B each: pubkey + daily_cap + tx_cap) |

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

### Approval PDA — `["approval", mint, owner, destination]` — 73 bytes

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Discriminator (`veilwl\0\0`) |
| 8 | 32 | `root` — Merkle root at time of approval |
| 40 | 32 | `destination` — approved destination address |

## Devnet Proof

**Program:** [`J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1`](https://solscan.io/account/J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1?cluster=devnet)

Every feature verified on-chain with real Token-2022 transfers:

| Step | Action | Result | Solscan |
|------|--------|--------|---------|
| 1 | Create Token-2022 mint with transfer hook | Mint [`Fuye3g...`](https://solscan.io/account/Fuye3gLYxvRK6ucJxfuUJ9bjdACs3QxoGHr7sYhGWTBZ?cluster=devnet) | [tx](https://solscan.io/tx/3GUdCwwheSik77phHmEWYvpfTfbibRbNHMLW57jSHcvtUZogro6edN1mNMNKkdjbLzep6WUxG3i8DNzHbCCRJcs3?cluster=devnet) |
| 2 | Initialize ExtraAccountMetas (3 PDAs: policy, tracker, approval) | PDA [`6KHwi...`](https://solscan.io/account/6KHwiN7msqKBjZTyEDPRdXqEt94qFQmWA87a9RFm8Xis?cluster=devnet) | [tx](https://solscan.io/tx/3o8XGumMgKeDDW5af56CTYxW686qbWTMh6RknWQq7UsFX3ixRvRQREBZvrfSmGmkZUKDuSX2brybCtVURGWQfprN?cluster=devnet) |
| 3 | CreatePolicy (tx_cap=1, daily=5, monthly=50, velocity=5/60s) | Policy [`5YUZS...`](https://solscan.io/account/5YUZSCSVDBGbtfVHTy9qt231j1KmsrwjeRT2EHu2G1qe?cluster=devnet) | [tx](https://solscan.io/tx/rP1gBj4A3PjpahVicgSBYJhKK8ELnPcYbvZyPhPzqP5bfvnM2J4WRztZAQMR5YJ5CcAJY77zFDj2e5AfvXUiup2?cluster=devnet) |
| 4 | Mint 100 tokens to owner | ATA [`C2wiN...`](https://solscan.io/account/C2wiNUg1pY6WSvuR6kFfgUp2UQzw8JiXzv6Cwbfekfz6?cluster=devnet) | [tx](https://solscan.io/tx/4nL2JxWw7ExR7JQ3Cn9uuku7uGZNzZMxJVdgDsVGznRcBcAERaJW5z91N8BLCwGJq2Rr5KDoS6uD3sV6zKZrkyZc?cluster=devnet) |
| 5 | Create destination wallet + ATA | Dest [`FPYuT...`](https://solscan.io/account/DdhgnpF3w6ENGdz7JofdAPbddSrWjMNtKGSN8QUqb5vp?cluster=devnet) | [tx](https://solscan.io/tx/5Hae5HKU5Zhc7vLffYEd6R7utPE9Vhgw5rJVk8iSS3Mfta5SgC6LC1CNsrYbyJ4UeoFWpmwujh5ZWuv1jiembJUG?cluster=devnet) |
| 6 | **Transfer 0.5 tokens** (within tx_cap=1) | **Success** | [tx](https://solscan.io/tx/56JHcd4L9PAGq7WeVFs6NxuMksrTsK8r45AQfggSxGHuCbMvkGNVWtVNRZDpETaeR4d1bksEoj1zpwUgbWMtenE4?cluster=devnet) |
| 7 | **Transfer 2 tokens** (exceeds tx_cap=1) | **Rejected** `0x5601` | [logs](https://solscan.io/tx/56JHcd4L9PAGq7WeVFs6NxuMksrTsK8r45AQfggSxGHuCbMvkGNVWtVNRZDpETaeR4d1bksEoj1zpwUgbWMtenE4?cluster=devnet) |
| 8 | UpdatePolicy (lower daily_cap to 1 token) | Updated | [tx](https://solscan.io/tx/65XFCzfnj61ZoHG54zwmZRsbwWCHtyEjToA5m33FGPb5FkXRRUAFF9yeqDW1fiQ9AC1FbDJZ9fwRJEJQaY1URdhy?cluster=devnet) |
| 9 | **Transfer 0.8 tokens** (0.5 already spent + 0.8 > daily_cap=1) | **Rejected** `0x5602` | [logs](https://solscan.io/tx/65XFCzfnj61ZoHG54zwmZRsbwWCHtyEjToA5m33FGPb5FkXRRUAFF9yeqDW1fiQ9AC1FbDJZ9fwRJEJQaY1URdhy?cluster=devnet) |
| 10 | AddDelegation (delegate with sub-caps) | Delegate [`BsjTb...`](https://solscan.io/account/BsjTbgiNPZWMNbc6XM4JwDaD2xxTG2RdKqJe3zEUu1Mr?cluster=devnet) | [tx](https://solscan.io/tx/cuumd6wi4oRyqvXdQQpwJg3Zescxdkgt18JANQbS8wEhq6ojjwaViJxmEynP5PmdtMWFFYukuWf56sbpGdFumEX?cluster=devnet) |
| 11a | UpdatePolicy to whitelist mode (mode=0) | Updated | [tx](https://solscan.io/tx/sUHpu3vpxGsWRQ5yTepPq2GvG8dhHTVTjTVbTdUT61PxyKs9HNZYFAS6JeyFhzLgXdPjpejZzwnzTrs9zMSAyBi?cluster=devnet) |
| 11b | SetWhitelistRoot (SHA256 Merkle root) | Root set | [tx](https://solscan.io/tx/kFu7ujE3Vgzz3gyVRLXPMimwvUfV552LXCH1mD4UCKXAjNuV4CCcbxWqq9qhe2g9oqXxiyWKmzXFsdeV2FGUFgB?cluster=devnet) |
| 11c | ApproveDestination (Merkle proof verified on-chain) | Approval [`FZXEr...`](https://solscan.io/account/FZXErmhqYkMgHuvKe9WMSmXKi8qsyva7wMzt9B2dNPb6?cluster=devnet) | [tx](https://solscan.io/tx/3iYkdgaSRU8H62UapMFg55rUCnVxnv2gi9JWmfVyunyBTmyBjG1DehUXMGV8A4B4L7FCPkzjisco19gwkxFRZQB1?cluster=devnet) |
| 12 | **Transfer 0.1 tokens** (whitelist approved destination) | **Success** | [tx](https://solscan.io/tx/5mnyp6djDKasdJQQK8qi41qys4BUSjigh3xZcd6wfCa7UCzYtcarbqDXw644MGYp5ZYhh4LB8TnAZnA8he66gq3L?cluster=devnet) |
| 13 | RevokeApproval (close approval PDA, reclaim rent) | Revoked | [tx](https://solscan.io/tx/4tc5XNnvjsgBYbs5iAD3iAeJse3NdySHuT9EKb2jnLyP7PLFyDdd3PGizjZRsNz77YDoGn8EzYrTaCei1RVPWYw3?cluster=devnet) |
| 14 | **Transfer 0.1 tokens** (after revocation) | **Rejected** `0x5600` | [logs](https://solscan.io/tx/4tc5XNnvjsgBYbs5iAD3iAeJse3NdySHuT9EKb2jnLyP7PLFyDdd3PGizjZRsNz77YDoGn8EzYrTaCei1RVPWYw3?cluster=devnet) |

**Error codes:** `0x5600`=RecipientNotWhitelisted, `0x5601`=AmountExceedsTxCap, `0x5602`=DailyCapExceeded, `0x5603`=MonthlyCapExceeded, `0x5604`=VelocityLimitExceeded, `0x5605`=TimeWindowViolation

### Round 2 — Remaining Features

| Test | Action | Result | Solscan |
|------|--------|--------|---------|
| A1 | Velocity: transfer 1/2 | **Success** | [tx](https://solscan.io/tx/3EELTz5KcHVnMWmAkCkSRDoFEHgY3Uk8iVtpfqgP869KMnohX8bCVs6dq5uqspkoYSGHfDgnPS8imVRmE5qQPUuL?cluster=devnet) |
| A2 | Velocity: transfer 2/2 | **Success** | [tx](https://solscan.io/tx/43ASGjZYHss2wJ2roxkzsZmSDLGT3rShxumkdq3dJN6v9nprYoCTtCCm7xa9VMRY883FHkLcECcqSkE6TyQk4YYX?cluster=devnet) |
| A3 | **Velocity: transfer 3/2** (exceeds max 2 per 300s) | **Rejected** `0x5604` | simulated |
| B1 | **Transfer outside allowed hours** (window excludes current UTC hour) | **Rejected** `0x5605` | simulated |
| B2 | UpdatePolicy to include current hour | Updated | [tx](https://solscan.io/tx/2ipiTHxi8HRSBSoNZKD4Jt9pFjHmReQisbM7ixMCazGbEQQnATDYLCAoGXDiGgqauSjRiGaQB9pFsZEcLboN8hFR?cluster=devnet) |
| B3 | **Transfer within allowed hours** | **Success** | [tx](https://solscan.io/tx/5wBsHWJantWaEiHCTf8ma8kTFcuWHZmTBrpiUH7uDqhGbaPFnrR9GVa9u3Ls8RBLprfftb2SFfaowPmv5VVLjcbg?cluster=devnet) |
| C1 | Transfer 0.3 tokens (within monthly_cap=0.5) | **Success** | [tx](https://solscan.io/tx/2EnGS3T165kow2EG6CHU5jCyBvWuFpAAX4MGEurdHhVkcSy59vXWGomCMj2KApnA1phZWJEMdRgqkeBMeqFtoHmj?cluster=devnet) |
| C2 | **Transfer 0.3 tokens** (cumulative 0.6 > monthly_cap=0.5) | **Rejected** `0x5603` | simulated |
| D1 | AddDelegation (daily=1, tx=0.5) + Token-2022 approve | Configured | [delegation](https://solscan.io/tx/3VuJYzrbhfmN5Yn4JjJq5N8Kq7ZUQSBBB2eSFJemfnaxsFr9LYSiPuJvxeg2cGhGSG1J2b1vnSfP1NVw5n3PuWcD?cluster=devnet), [approve](https://solscan.io/tx/4nVgih7v7TpMrrNEyv68ufD5tYDjW7R7aiXcEi8CPJtygUYxiEDHCZ6gkmjhSb14qe3AQRs2Dy5orwLiRdtjJZ7B?cluster=devnet) |
| D2 | **Delegate transfers 0.1 tokens** (within sub-cap) | **Success** | [tx](https://solscan.io/tx/4pHwqxg5V5R6eJGxUXcrD4fGKw9u3XKXbdyging16sMUHs7XyS91eefdGnqNhsb5jaUscpqoifreVVxvkMjShzR8?cluster=devnet) |
| D3 | **Delegate transfers 0.6 tokens** (exceeds delegate tx_cap=0.5) | **Rejected** `0x5601` | simulated |
| E1 | SetWhitelistRoot + ApproveDestination (Merkle proof) | Approved | [root](https://solscan.io/tx/5oqii5iVZeEDPnxoVtjfsmfHK68JnZZoA1cw6JADMuPkPDX1RT8EYCBum4ZYM3RqjTEeNTP2QHT1VZiVYfTvsBhu?cluster=devnet), [approve](https://solscan.io/tx/2TbuKPUqWTQccj8DHy8BUJEQrR5npWXeZBirgoWNBNTiDRaPj16L77fausnmaxYAq9nDCtuFPkE3ZszJwyccMNkk?cluster=devnet) |
| E2 | Transfer with valid approval | **Success** | [tx](https://solscan.io/tx/379i2Jo6qSwUdJStbntaoeBWWfxCxHHPtAaU7BAM21TtSMGdmP3tzVnXGwRqeLFxAgZAQu9UoBM4xqqJTnay4gte?cluster=devnet) |
| E3 | Rotate whitelist root to new tree | Rotated | [tx](https://solscan.io/tx/37FmHmK78cuFJPzr582nvEDQjGGft3PKZneVaUaLCuxShgaxQpN8E342uRE65e7DMGVfH8EcSEPW2MtAHsQgpHPc?cluster=devnet) |
| E4 | **Transfer with stale approval** (old root != new root) | **Rejected** `0x5600` | simulated |

> **Note:** Rejected transfers are simulated by the RPC (preflight check) and never land on-chain — this is standard Solana behavior. The error codes in the simulation logs prove the hook executed and enforced the correct policy rule.

### On-chain Accounts

| Account | Address | Solscan |
|---------|---------|---------|
| Program | `J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1` | [link](https://solscan.io/account/J39uNr5qGDwFXzZ9w2YtPeVenQRQztLc68QXmFL4Diz1?cluster=devnet) |
| Mint (Round 1) | `Fuye3gLYxvRK6ucJxfuUJ9bjdACs3QxoGHr7sYhGWTBZ` | [link](https://solscan.io/account/Fuye3gLYxvRK6ucJxfuUJ9bjdACs3QxoGHr7sYhGWTBZ?cluster=devnet) |
| Mint (Velocity) | `4mHDNAghRCF1Uu3gzCFRtV7QAGgQgMHbG5iFrupcqYTj` | [link](https://solscan.io/account/4mHDNAghRCF1Uu3gzCFRtV7QAGgQgMHbG5iFrupcqYTj?cluster=devnet) |
| Mint (Time Window) | `49BaXsjn9cq4atntFb6N5CWtQtGU1FBJvoFQVSgKZtQX` | [link](https://solscan.io/account/49BaXsjn9cq4atntFb6N5CWtQtGU1FBJvoFQVSgKZtQX?cluster=devnet) |
| Mint (Monthly Cap) | `82D3mFLcb9ehsSqDm4LhzZYPyuvzhoysGSBYmoY6ARYG` | [link](https://solscan.io/account/82D3mFLcb9ehsSqDm4LhzZYPyuvzhoysGSBYmoY6ARYG?cluster=devnet) |
| Mint (Delegation) | `DzXNGrGbkxeRNvS6z9gtMHDerkCB4Wqkoe2JxUmeV25b` | [link](https://solscan.io/account/DzXNGrGbkxeRNvS6z9gtMHDerkCB4Wqkoe2JxUmeV25b?cluster=devnet) |
| Mint (Stale Approval) | `A3k5iGWmPXaKEzD38tZmUy59Ec6cHc4rFYxaCDGWmSFF` | [link](https://solscan.io/account/A3k5iGWmPXaKEzD38tZmUy59Ec6cHc4rFYxaCDGWmSFF?cluster=devnet) |

## Build & Test

```bash
# Build the SBF binary
cargo build-sbf

# Copy to test fixtures
cp target/deploy/veil_hook.so programs/veil-hook/tests/fixtures/

# Run integration tests (36 tests, all passing)
cargo test --test integration
```

Requires Rust + Solana CLI toolchain (`cargo build-sbf`). Outputs `target/deploy/veil_hook.so`.

## Test Coverage

36 integration tests via [mollusk-svm](https://crates.io/crates/mollusk-svm):

- **CreatePolicy** — success, already-initialized, missing signer, invalid mode
- **UpdatePolicy** — success, wrong owner rejection
- **AddDelegation** — success with cap verification
- **Execute** — basic transfer, all cap types (tx/daily/monthly), velocity limits + window reset, time-of-day windows, daily/monthly counter resets, cumulative tracking, exact boundary conditions, zero-caps-as-unlimited
- **Delegation** — successful delegate transfer, delegate tx cap enforcement, unauthorized wallet rejection
- **Whitelist** — set root (success + wrong owner), approve destination (success + invalid proof), execute with approval, execute without approval (reject), stale approval after root rotation (reject), second destination approval
- **Revoke** — revoke approval success
- **InitExtraAccountMetas** — full TLV + seed encoding verification (3 entries), already-initialized guard

## Design Decisions

- **Pinocchio over Anchor** — Direct account data access, ~5-10x less CU than Anchor's deserialization overhead
- **Zero-copy state** — All reads/writes go directly to account data slices. No alloc, no serde, no intermediate structs
- **Owner-keyed PDAs** — PDAs use the token account owner (via `AccountData` seed resolution at index 0, offset 32), not the transfer authority. This makes delegation composable without separate PDA trees
- **Shared tracker** — Owner and delegates share one tracker. Delegate sub-caps are enforced as `min(delegate_cap, global_cap)` — delegates can never exceed global limits
- **SHA256 Merkle proofs** — Uses the `sol_sha256` syscall (~100 CU/hash). Approval PDA pattern keeps the hot path fast — proof verification only at approval time, not on every transfer
- **Root rotation = auto-invalidation** — Approval PDAs store the root they were approved under. Rotating the policy root instantly invalidates all existing approvals without on-chain iteration
- **Destination = token account address** — More granular than wallet-level whitelisting. ExtraAccountMeta resolves it via `AccountKey(2)`

## Roadmap

- [ ] Groth16 ZK proof verification (Poseidon Merkle membership)
- [ ] Blacklist mode with on-chain recipient entries
- [ ] Per-delegate spend tracking (separate counters)
- [ ] `RemoveDelegation` instruction
- [ ] TypeScript client SDK + React hooks
- [ ] Mainnet deployment

## License

[MIT](LICENSE)
