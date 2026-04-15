# Veil — Integration Guide & Use Cases

Real-world ways to integrate Veil's transfer hook into your project. Every pattern below works today on devnet — no theoretical features, no roadmap items.

---

## 1. AI Agent Spending Controls

**Problem:** You give an AI agent a wallet to execute trades, pay for API calls, or manage funds. Nothing stops it from draining everything in one hallucination.

**Solution:** Mint your operational tokens with Veil's transfer hook. Set per-tx caps so a single bad trade can't exceed $100. Set daily caps so a runaway loop can't burn through more than $1,000/day. The agent literally cannot bypass these — they're enforced at the token level, not the wallet level.

```
CreatePolicy:
  tx_cap:      100_000_000   (100 USDC)
  daily_cap:   1_000_000_000 (1,000 USDC)
  monthly_cap: 10_000_000_000 (10,000 USDC)
  mode: open
```

**Delegation variant:** Keep the main wallet's keys cold. Use `AddDelegation` to give the agent a sub-limited key with even tighter caps than the global policy. Revoke it anytime by rotating the policy.

---

## 2. Corporate Treasury & Payroll

**Problem:** A multisig approves a $50K monthly budget for a department. But once tokens hit the department wallet, there's no enforcement — they could send it all in one transaction.

**Solution:** Issue departmental stablecoins on a Veil-hooked mint. The policy enforces the budget programmatically:

```
CreatePolicy:
  tx_cap:      5_000_000_000  (5,000 — max single payment)
  daily_cap:   10_000_000_000 (10,000 — daily disbursement limit)
  monthly_cap: 50_000_000_000 (50,000 — monthly budget)
  mode: whitelist              (only approved vendors)
```

Then whitelist approved vendors via Merkle proof. The department can spend freely within limits to any approved vendor — no multisig needed for every payment. Add new vendors by updating the Merkle tree and calling `ApproveDestination`.

---

## 3. Parental Controls / Custodial Accounts

**Problem:** You want to give a minor or dependent access to funds, but with guardrails.

**Solution:** Create a token account for them on a Veil-hooked mint. Set spending limits and restrict where they can send:

```
CreatePolicy:
  tx_cap:      50_000_000     (50 — max per purchase)
  daily_cap:   200_000_000    (200 — daily allowance)
  velocity_max: 10            (max 10 transactions)
  velocity_window: 3600       (per hour)
  time_start_h: 8             (only 8am-10pm UTC)
  time_end_h: 22
  mode: whitelist              (only approved merchants)
```

The child can tap-to-pay at approved stores during allowed hours. They can't drain the account, send to random wallets, or go on a 3am spending spree.

---

## 4. DAO Committee Spending

**Problem:** A DAO votes to allocate funds to a working group. They want oversight without requiring a governance vote for every expense.

**Solution:** The DAO treasury mints on a Veil-hooked token. Each committee member gets a delegation with sub-caps:

```
CreatePolicy (committee wallet):
  tx_cap:      10_000_000_000  (10,000 — global cap)
  daily_cap:   50_000_000_000  (50,000)
  monthly_cap: 200_000_000_000 (200,000 — quarterly budget)
  mode: open

AddDelegation (member A):
  daily_cap:   5_000_000_000   (5,000/day for this member)
  tx_cap:      2_000_000_000   (2,000/tx for this member)

AddDelegation (member B):
  daily_cap:   5_000_000_000
  tx_cap:      2_000_000_000
```

Each member can spend independently within their sub-limits. The global caps ensure the total budget can't be exceeded even if both members max out simultaneously.

---

## 5. Vesting with Spending Rails

**Problem:** Standard vesting releases tokens on a schedule, but once unlocked, there's no control over how fast they're sold.

**Solution:** Vest into a Veil-hooked token account with velocity and daily caps:

```
CreatePolicy:
  tx_cap:      0               (unlimited per-tx)
  daily_cap:   1_000_000_000   (1,000/day sell limit)
  monthly_cap: 10_000_000_000  (10,000/month sell limit)
  velocity_max: 3              (max 3 sells per window)
  velocity_window: 86400       (per day)
  mode: open
```

Tokens vest normally, but the recipient can only sell 1,000/day — preventing a cliff-unlock dump. The velocity limit prevents splitting into many small transactions to circumvent the daily cap within a single block.

---

## 6. Subscription / Recurring Payment Rails

**Problem:** You want to authorize a service to pull recurring payments from your wallet, but don't want to give unlimited approval.

**Solution:** Use delegation as a pull-payment authorization:

```
CreatePolicy (your wallet):
  tx_cap:      100_000_000     (100 — max single charge)
  daily_cap:   100_000_000     (100 — one charge per day max)
  monthly_cap: 3_000_000_000   (3,000 — monthly billing cap)
  mode: whitelist

AddDelegation (service's hot wallet):
  daily_cap:   100_000_000     (100/day sub-cap)
  tx_cap:      100_000_000     (100/tx sub-cap)
```

The service can charge exactly $100/day. If they try to double-charge, the daily cap blocks it. If they try a big charge, the tx cap blocks it. Whitelist mode ensures they can only send to their own known address.

---

## 7. Gaming / In-App Currency

**Problem:** You want an in-game token economy with anti-exploit protections.

**Solution:** Game currency on a Veil-hooked mint with velocity controls:

```
CreatePolicy:
  velocity_max: 20             (max 20 trades per window)
  velocity_window: 60          (per minute)
  daily_cap:   10_000_000_000  (10,000 — daily trade volume cap)
  mode: whitelist               (only game marketplace contracts)
```

Players can trade freely within normal gameplay patterns. Bot-like behavior (hundreds of trades per minute) gets blocked by velocity limits. The whitelist ensures tokens can only flow through official game contracts.

---

## Integration Patterns

### Pattern A: Wrap Existing Tokens

Don't want to change your existing token? Create a Veil-hooked wrapper:

1. Create a Veil-hooked mint
2. Build a vault program that accepts deposits of your existing token and mints 1:1 wrapped tokens
3. Users operate with the wrapped token (policy-enforced)
4. Unwrap back to the original token when needed

### Pattern B: Native Policy Tokens

For new projects, mint directly on a Veil-hooked mint. Every transfer is policy-enforced from day one. No wrapping needed.

### Pattern C: Multi-Policy per Mint

One mint can have different policies per owner. User A might have strict caps while User B has unlimited spending. Policies are per `(mint, owner)` pair — the mint is shared, the rules are personal.

---

## CU Budget

All numbers measured on devnet:

| Operation | Compute Units |
|-----------|--------------|
| Execute (no whitelist) | ~3,500 CU |
| Execute (with whitelist check) | ~5,000 CU |
| CreatePolicy | ~7,800 CU |
| UpdatePolicy | ~260 CU |
| AddDelegation | ~580 CU |
| SetWhitelistRoot | ~230 CU |
| ApproveDestination (1-level proof) | ~3,700 CU |
| RevokeApproval | ~1,800 CU |

For reference, a standard Token-2022 transfer without hooks uses ~18,000 CU. Veil adds ~3,500-5,000 CU on top.
