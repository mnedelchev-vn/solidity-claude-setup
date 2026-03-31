# Protocol Context Report — WETH9

> Generated: 2026-03-31
> Analyzed: `contracts/WETH9.sol`
> Docs: https://ethereum.org/wrapped-eth/

---

## Step 1 — High Level Report

### Protocol Overview

`WETH9` is a **token wrapper** protocol — the canonical Wrapped Ether contract originally deployed by Dapphub in December 2017. It belongs to the **infrastructure / token primitive** category, not a DEX or lending protocol.

Its purpose is to bridge the incompatibility between native ETH and the ERC-20 token standard. ETH predates ERC-20 and cannot natively conform to the token interface most DeFi applications expect. WETH9 resolves this by accepting native ETH deposits and minting an equivalent 1:1 ERC-20 token (WETH). The reverse — burning WETH to reclaim ETH — is also supported.

The contract is a minimal, self-contained ERC-20 implementation with no admin, no owner, no governance, no fees, no pause mechanism, and no upgradability. `totalSupply` is always exactly equal to `address(this).balance`, enforcing the strict 1:1 peg at all times. A sentinel value of `uint(-1)` (`type(uint256).max` in modern Solidity) is used to represent infinite/unlimited allowances, which skips the allowance decrement on `transferFrom`. The fallback function transparently routes any raw ETH transfer to `deposit()`, making wrapping ergonomic. Roughly ~3% of all circulating ETH sits in WETH contracts, making this one of the most critical pieces of DeFi infrastructure.

Written in Solidity 0.4.18 — pre-`SafeMath`, pre-custom-errors, pre-`emit` keyword for events, and with the old-style unnamed payable fallback syntax. Users must retain native ETH for gas fees, as WETH cannot pay transaction costs directly.

---

### Actors

| Actor | Type | Description |
|---|---|---|
| **User** | EOA or Smart Contract | Any address that wraps ETH via `deposit()` or unwraps via `withdraw()`. No access restrictions. |
| **Token Holder** | EOA or Smart Contract | Any address with a WETH balance that can call `transfer()` to move tokens directly. |
| **Spender** | EOA or Smart Contract | An address granted an allowance via `approve()`, permitted to call `transferFrom()` on behalf of the approver. |

There is **no owner, admin, operator, or any privileged role** of any kind.

---

### Entry Points — `WETH9.sol`

| Method | Visibility | Payable | Mirror / Opposing Method |
|---|---|---|---|
| `deposit()` | `public` | yes | `withdraw(uint wad)` |
| `withdraw(uint wad)` | `public` | no | `deposit()` |
| `fallback()` *(unnamed)* | `public` | yes | *(delegates to `deposit()` — no direct mirror)* |
| `approve(address guy, uint wad)` | `public` | no | *(revoke by calling `approve(guy, 0)`)* |
| `transfer(address dst, uint wad)` | `public` | no | *(delegates internally to `transferFrom` — no opposing method)* |
| `transferFrom(address src, address dst, uint wad)` | `public` | no | *(no mirror)* |

**Symmetry notes:**
- `deposit` / `withdraw` are direct structural mirrors: one wraps ETH → WETH, the other unwraps WETH → ETH.
- The unnamed fallback function is a transparent alias for `deposit()` — any ETH sent directly to the contract address triggers a wrap.
- `transfer` is a thin wrapper that delegates entirely to `transferFrom(msg.sender, dst, wad)`.

---

## Step 2 — In-Depth Level Report

### 1. Access Control Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                      ACCESS CONTROL                              │
├──────────────┬───────────────────────────────────────────────────┤
│ Role         │ Permitted Methods                                 │
├──────────────┼───────────────────────────────────────────────────┤
│ ANY address  │ deposit()           payable, no restrictions      │
│ (no roles)   │ withdraw(uint)      balance check only            │
│              │ fallback()          payable, delegates to deposit  │
│              │ approve(addr,uint)  no restrictions               │
│              │ transfer(addr,uint) balance check only            │
│              │ transferFrom(...)   balance + allowance checks    │
└──────────────┴───────────────────────────────────────────────────┘
```

There are **zero privileged roles**. Authorization is purely balance-based (`balanceOf[src] >= wad`) and allowance-based (`allowance[src][msg.sender] >= wad`). The `uint(-1)` allowance sentinel bypasses the allowance deduction step on `transferFrom` — the standard "infinite approval" pattern.

**Role responsibilities:**
- No role exists with administrative power. Every method is publicly accessible.
- Self-custody is enforced entirely by EVM balance and allowance accounting — there is no admin escape hatch.

---

### 2. Funds Flow Diagram

```
                     ┌───────────────────────────────────────────────┐
                     │                   WETH9                       │
                     │                                               │
 User ─deposit()──▶  │  balanceOf[user] += msg.value                 │
 (sends ETH)         │  contract ETH balance += msg.value            │
                     │  ── 1:1 peg always maintained ──              │
                     │  totalSupply() == address(this).balance        │
                     │                                               │
 User ─fallback()──▶ │  → delegates to deposit()                     │
 (raw ETH transfer)  │    same flow as above                         │
                     │                                               │
 User ─withdraw()──▶ │  require balanceOf[user] >= wad               │
 (burns WETH)        │  balanceOf[user] -= wad                       │
                     │  msg.sender.transfer(wad) ──────────▶ ETH out │
                     │  contract ETH balance -= wad                  │
                     │                                               │
 User ─transfer()──▶ │  → delegates to transferFrom(msg.sender, ...) │
                     │  balanceOf[src] -= wad                        │
                     │  balanceOf[dst] += wad                        │
                     │  (no ETH movement — WETH balance shift only)  │
                     │                                               │
 Spender             │  check allowance[src][spender] >= wad         │
 ─transferFrom()──▶  │  (skip deduct if allowance == uint(-1))       │
                     │  allowance[src][spender] -= wad               │
                     │  balanceOf[src] -= wad                        │
                     │  balanceOf[dst] += wad                        │
                     └───────────────────────────────────────────────┘
```

**Peg invariant:** `totalSupply() == address(this).balance` always holds. `deposit` adds to both simultaneously; `withdraw` subtracts from both simultaneously. There is no mechanism to mint WETH without depositing an equal amount of ETH.

---

### 3. Module & Internal Call Diagram

The protocol is a **single, standalone contract** with no periphery, no proxy, and no cross-contract calls.

```
┌──────────────────────────────────────────────────────┐
│                     WETH9.sol                        │
│                                                      │
│  External Entry Points        Internal Delegation    │
│  ─────────────────────        ──────────────────     │
│  fallback()        ─────────▶ deposit()              │
│  transfer()        ─────────▶ transferFrom()         │
│                                                      │
│  deposit()         (no internal calls)               │
│  withdraw()        (no internal calls)               │
│  approve()         (no internal calls)               │
│  transferFrom()    (no internal calls)               │
│                                                      │
│  State:                                              │
│   mapping(address => uint)              balanceOf    │
│   mapping(address => mapping(addr=>uint)) allowance  │
└──────────────────────────────────────────────────────┘
```

---

### 4. Dependencies

**None.** WETH9 has zero external contract calls, no oracle integrations, no library imports, and no inherited contracts. It is a fully self-contained implementation with no dependency surface.

```
┌──────────────────────────────────────┐
│  External Dependencies               │
│                                      │
│  Oracles:             NONE           │
│  DEX integrations:    NONE           │
│  Lending protocols:   NONE           │
│  Libraries:           NONE           │
│  Inherited contracts: NONE           │
│  External calls:      NONE           │
│                                      │
│  Only outbound interaction:          │
│  msg.sender.transfer(wad)            │
│  in withdraw() — native ETH to caller│
│  (not a contract dependency)         │
└──────────────────────────────────────┘
```

> **Docs context (ethereum.org):** The ownerless, immutable architecture is an intentional design decision — it makes the contract maximally trustless. As noted in the official Ethereum documentation, ~3% of all circulating ETH is locked in WETH contracts, underlining why no admin escape hatch should exist. Users must hold native ETH separately for gas since WETH cannot pay transaction fees directly.

---

*End of report.*
