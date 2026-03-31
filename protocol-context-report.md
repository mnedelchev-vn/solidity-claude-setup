# Protocol Context Report — StakingPool

> Generated: 2026-03-31
> Analyzed: `contracts/StakingPool.sol`

---

## Step 1 — High Level Report

### Protocol Overview

`StakingPool` is a single-asset staking protocol where users deposit an ERC20 token and earn yield from two sources: (1) fees charged on other users' staking and unstaking actions, and (2) voluntary token injections via `donateToPool`. The protocol belongs to the **staking / yield-distribution** category.

Reward distribution uses a round-based cumulative dividend-per-token mechanism. Each time fees or donations are added, a new round is opened and the marginal `dividendPerToken` is accumulated into a global `totalDividends` tracker. A `payouts` mapping records the cumulative value at each round boundary. A staker's pending reward is the difference between the current cumulative value and the value at the round when the staker last interacted, multiplied by their stake — all scaled by `SCALING (1e18)` to preserve precision across integer arithmetic.

The contract is paused per OpenZeppelin's `Pausable`, gating `stake` and `donateToPool` but intentionally leaving `unstake` and `claimReward` unaffected so users can always exit. The owner can also recover arbitrary ERC20 tokens or native ETH, subject to a guard ensuring the staking token balance never drops below `totalStakes`.

Fees are capped at 10% (`FEE_DENOMINATOR / 10 = 1000 bps`) each for staking and unstaking. A first depositor (when `totalStakes == 0`) is exempt from staking fee — this prevents a zero-division path in `_addPayout`. Similarly, the unstaking fee is only applied when `totalStakes > 0` after the withdrawal is deducted.

The protocol has no governance token, no time-locks, no vesting, and no external oracle dependencies. It is a minimal, self-contained staking contract.

---

### Actors

| Actor | Type | Description |
|---|---|---|
| **Owner** | EOA or Smart Contract | Deployed address (set in constructor via `Ownable`). Controls pausing, fee configuration, and asset recovery. |
| **Staker** | EOA or Smart Contract | Any address that calls `stake()`. Earns dividends proportional to their share of `totalStakes`. |
| **Donor** | EOA or Smart Contract | Any address that calls `donateToPool()`. Injects tokens into the pool as rewards without receiving a stake position. Can overlap with a Staker. |

---

### Entry Points per Contract

#### `StakingPool.sol`

| Method | Visibility | Modifier(s) | Mirror / Opposing Method |
|---|---|---|---|
| `stake(uint256 _amount)` | `external` | `whenNotPaused` | `unstake(uint256 _amount)` |
| `unstake(uint256 _amount)` | `external` | — | `stake(uint256 _amount)` |
| `claimReward()` | `external` | — | *(no direct mirror; reward auto-claimed on stake/unstake)* |
| `donateToPool(uint256 _amount)` | `external` | `whenNotPaused` | *(no mirror — one-directional injection)* |
| `pause()` | `public` | `onlyOwner` | `unpause()` |
| `unpause()` | `public` | `onlyOwner` | `pause()` |
| `setFees(uint16, uint16)` | `public` | `onlyOwner` | *(no mirror — read via public state vars `stakingFee`, `unstakingFee`)* |
| `recover(address, uint256)` | `public` | `onlyOwner` | *(no mirror)* |
| `getPendingReward(address)` | `public view` | — | *(read-only, no mirror)* |

**Symmetry notes:**
- `stake` / `unstake` are structural mirrors: both auto-claim any pending reward during execution.
- `pause` / `unpause` are direct mirrors.
- `claimReward` is a standalone reward-pull; its behavior is a subset of what `stake` and `unstake` already do internally.

---

## Step 2 — In-Depth Level Report

### 1. Access Control Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ACCESS CONTROL                               │
├──────────────┬──────────────────────────────────────────────────────┤
│ Role         │ Permitted Methods                                     │
├──────────────┼──────────────────────────────────────────────────────┤
│ Owner        │ pause()                                               │
│ (onlyOwner)  │ unpause()                                             │
│              │ setFees(uint16, uint16)                               │
│              │   └─ capped: each fee ≤ 1000 bps (10%)               │
│              │ recover(address, uint256)                             │
│              │   └─ ETH: sends ETH to owner()                       │
│              │   └─ ERC20: safeTransfer; guard: balance ≥ totalStakes│
├──────────────┼──────────────────────────────────────────────────────┤
│ Staker       │ stake(uint256)       [whenNotPaused]                  │
│ (any EOA /   │ unstake(uint256)     [no pause restriction]           │
│  contract)   │ claimReward()        [no pause restriction]           │
│              │ getPendingReward()   [view]                           │
├──────────────┼──────────────────────────────────────────────────────┤
│ Donor        │ donateToPool(uint256) [whenNotPaused]                 │
│ (any EOA /   │   └─ reverts if totalStakes == 0                      │
│  contract)   │                                                       │
└──────────────┴──────────────────────────────────────────────────────┘
```

**Role responsibilities:**
- **Owner** — protocol administrator. Can halt user-facing entry functions, tune fee economics, and rescue stuck tokens. Cannot directly steal staker funds due to the `balance ≥ totalStakes` guard in `recover`.
- **Staker** — primary protocol participant. Stakes tokens, accrues dividend-based rewards, and can exit at any time even when paused.
- **Donor** — permissionless reward injector. Adds yield to all current stakers without acquiring a stake position.

---

### 2. Funds Flow Diagram

```
                         ┌──────────────────────────────────────────┐
                         │              StakingPool                 │
                         │                                          │
  User ──stake()──────▶  │  token.transferFrom(user, pool, amount)  │
                         │  ├─ fee (if totalStakes > 0)             │
                         │  │   └─▶ _addPayout(fee)  ──────────────▶ distributed to all stakers
                         │  └─ net = amount - fee  ──▶ stakers[user].stakedTokens += net
                         │                              totalStakes += net
                         │  auto-claim pendingReward ──▶ token.transfer(user, reward)
                         │                                          │
  User ──unstake()──────▶│  stakers[user].stakedTokens -= amount    │
                         │  totalStakes -= amount                   │
                         │  fee (if totalStakes > 0 after deduct)   │
                         │  └─▶ _addPayout(fee) ───────────────────▶ distributed to remaining stakers
                         │  net = amount - fee + pendingReward      │
                         │  token.transfer(user, net) ◀─────────────┘
                         │                                          │
  User ──claimReward()──▶│  pendingReward = getPendingReward(user)  │
                         │  token.transfer(user, reward) ◀──────────┘
                         │                                          │
  Donor ─donateToPool()─▶│  token.transferFrom(donor, pool, amount) │
                         │  └─▶ _addPayout(amount) ───────────────▶ distributed to all stakers
                         │                                          │
  Owner ──recover()─────▶│  [ERC20] safeTransfer(owner, amount)     │
                         │          guard: balance ≥ totalStakes    │
                         │  [ETH]   owner.call{value: amount}()     │
                         └──────────────────────────────────────────┘
```

**Internal `_addPayout(fee)` flow:**
```
available = (fee × SCALING) + scaledRemainder
dividendPerToken = available / totalStakes
scaledRemainder  = available % totalStakes        ← dust carried forward

totalDividends  += dividendPerToken
payouts[round]   = payouts[round - 1] + dividendPerToken
round           += 1
```

**`getPendingReward(staker)` formula:**
```
stakerRound = stakers[staker].round  (decremented by 1 if > 0)
reward = (totalDividends - payouts[stakerRound]) × stakedTokens / SCALING
```

---

### 3. Module & Internal Call Diagram

The protocol is a single-contract, no-periphery design.

```
┌───────────────────────────────────────────────────────┐
│                    StakingPool.sol                    │
│                                                       │
│  External Entry Points          Internal              │
│  ──────────────────────         ────────              │
│  stake()          ──────────▶  _addPayout()           │
│                   ──────────▶  getPendingReward()     │
│                                                       │
│  unstake()        ──────────▶  _addPayout()           │
│                   ──────────▶  getPendingReward()     │
│                                                       │
│  claimReward()    ──────────▶  getPendingReward()     │
│                                                       │
│  donateToPool()   ──────────▶  _addPayout()           │
│                                                       │
│  recover()        ──────────▶  (none; direct transfer)│
│                                                       │
│  State stores:                                        │
│   mapping(address => Staker)  stakers                 │
│   mapping(uint256 => uint256) payouts                 │
│   uint256  round / totalStakes / totalDividends       │
│   uint256  scaledRemainder                            │
└───────────────────────────────────────────────────────┘
```

There is no periphery layer, no proxy, and no upgradability pattern. The contract is fully self-contained.

---

### 4. Dependencies

#### OpenZeppelin Contracts

```
┌─────────────────────────────────────────────────────┐
│              OpenZeppelin Dependencies              │
├──────────────────────┬──────────────────────────────┤
│ Import               │ Usage                        │
├──────────────────────┼──────────────────────────────┤
│ IERC20               │ Interface for staking token  │
│ SafeERC20            │ safeTransfer / safeTransferFrom on all token ops │
│ Pausable             │ pause() / unpause() + whenNotPaused modifier │
│ Ownable              │ onlyOwner modifier; owner() getter │
└──────────────────────┴──────────────────────────────┘
```

No external protocol integrations (no Uniswap, no Curve, no Chainlink, no other AMM/lending calls).
No price oracles.
No cross-chain components.
No flash loan receiver interfaces.

---

*End of report.*
