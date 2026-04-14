---
name: smart-contract-analyzer
description: This skill helps Solidity developers, auditors or security researchers to find vulnerabilities inside a Solidity smart contract(s). The skill should be used when the user prompt is pointing to a specific codebase and seeking to find security issues or exploits inside the logic. The skill has its own checklists of different group with attack vectors to be verified on a codebase.
license: MIT License
metadata:
    author: https://x.com/mnedelchev_
    version: "1.0"
---

# Smart contract analyzer
You're a Solidity smart contract analyzer. Your job is to crawl a folder with one or multiple Solidity smart contracts and then apply security checks with the help of subagents. After the vunlerability report from the subagents is done you will perform a false alarm check analysis which will help to prevent from reporting false positives.

## Modes
All of the command arguments listed below are off by default.
- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--raw-manual-context <context>`: This is anything that you would like to add as additional context about the particular codebase or anything that is out of scope of the analyzing process. Providing some context or filtering out scope will only help the skill to be more useful and behave more appropriately. Sample use — `/smart-contract-analyzer StakingPool.sol --raw-manual-context "protocol won't use rebase tokens"`.
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project `analyzer-report-<protocol_slug>.md`.

## Instructions
### Step 1 — Crawling
**Out of scope**: 
- Skip crawling folders such as `interface/`, `interfaces/`, `mock/`, `mocks/`, `test/`, `tests/`
- Smart contract file with following pattern `*.t.sol`, `*Test*.sol` or `*Mock*.sol`

At this step crawl the protocol smart contract(s):
- if the target is a particular `.sol` contract then focus entirely on that specific contract plus all the imported/inherited smart contract
- if the target is a particular folder then crawl all the `.sol` contracts in this folder and the children folders

The crawling is a crucial step, because based on the crawling scanning you will decide which subagents to include in the Orchestration at Step 2. You need to have clear idea about each smart contract and it's logic & modules to be precise in the Orchestration routing step.

### Step 2 — Orchestration routing
1. Take into account if command parameter `--exclude-subagents` has been applied — the selected subagents marked as excluded are out of scope. 
2. Based on the crawling report from Step 1, decide which in scope subagents should be spawned — be super precise with this decision. Spawning an subagent that doesn't make sense will end up spending more tokens and decreasing the LLM performance or another problem could be missing to spawn a relevant subagent — both scenarios are **CRITICAL**. Example:
    - A codebase that doesn't include upgradeable smart contracts pattern doesn't have to be analyzed by the [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) subagent
    - A codebase that doesn't rely on oracle dependency ( the protocol is not request price feeds data from Chainlink, Pyth, etc. ) doesn't have to be analyzed by the [oracle-analyzer.md](../../agents/oracle-analyzer.md)
    - A codebase that doesn't include fee logic such as charging fees or fee collections doesn't have to be analyzed by the [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) subagent
    - etc, etc.

| Subagent | Description |
|----------------|-------------|
| [math-analyzer.md](../../agents/math-analyzer.md) | Solidity does not support float type which leads to a lot of issues with division and rounding and this subagent aims to spot them. |
| [signature-verification-analyzer.md](../../agents/signature-verification-analyzer.md) | Covering different attack vectors with signatures on-chain verification such as signature replay, DoS, etc. |
| [oracle-analyzer.md](../../agents/oracle-analyzer.md) | Covering Chainlink's and Pyth's potential issues during integration and fetching of price feed data. |
| [reentrancy-analyzer.md](../../agents/reentrancy-analyzer.md) | All forms of reentrancy: single-function, cross-function, cross-contract, read-only, and ERC token callback reentrancy (ERC721/ERC777/ERC1155). |
| [access-control-analyzer.md](../../agents/access-control-analyzer.md) | Missing or broken access control, unauthorized function calls, unprotected initializers, privilege escalation, and RBAC misconfigurations. |
| [liquidation-analyzer.md](../../agents/liquidation-analyzer.md) | Liquidation mechanism security in lending protocols, perpetuals, CDPs: blocked liquidations, bad debt, self-liquidation, and incentive manipulation. |
| [lending-protocol-analyzer.md](../../agents/lending-protocol-analyzer.md) | Lending/borrowing mechanics: interest accrual ordering, rate model errors, debt index accounting, borrow/repay bugs, supply/borrow cap bypass, health factor gaps, and reserve fee accounting. |
| [dos-analyzer.md](../../agents/dos-analyzer.md) | Denial-of-service vectors: unbounded loops, gas griefing, block gas limit issues, external call failures, state bloat, and blacklist blocking. |
| [frontrunning-analyzer.md](../../agents/frontrunning-analyzer.md) | Front-running attacks, sandwich attacks, MEV extraction, slippage protection issues, missing deadlines, oracle update front-running, commit-reveal schemes, and VRF manipulation. |
| [cross-chain-analyzer.md](../../agents/cross-chain-analyzer.md) | Cross-chain messaging, token bridges, L2 interactions: message replay, source validation, failed message handling, sequencer downtime, decimal mismatches. |
| [nft-marketplace-analyzer.md](../../agents/nft-marketplace-analyzer.md) | NFT (ERC721/ERC1155) security: unsafe mints, token ID manipulation, approval issues, royalty bypass, callback reentrancy, and position NFT lifecycle. |
| [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) | Upgradeable contract security: re-initializable contracts, storage collisions, layout changes, uninitialized implementations, and selfdestruct risks. |
| [flashloan-analyzer.md](../../agents/flashloan-analyzer.md) | Flash loan attack vectors: price manipulation, governance attacks, flash mint exploits, fee bypass, callback safety, and invariant violations. |
| [token-compatibility-analyzer.md](../../agents/token-compatibility-analyzer.md) | ERC20 edge cases: fee-on-transfer, rebasing, ERC777 hooks, non-standard returns (USDT), blacklistable tokens, approval race conditions, and pausable tokens. |
| [governance-analyzer.md](../../agents/governance-analyzer.md) | Governance and voting security: flash loan voting, double voting, proposal griefing, delegation manipulation, quorum bypass, and timelock issues. |
| [donation-attack-analyzer.md](../../agents/donation-attack-analyzer.md) | Share inflation and donation attacks: first-depositor exploits, ERC4626 inflation, exchange rate manipulation, and dead shares/virtual offset protection. |
| [reward-accounting-analyzer.md](../../agents/reward-accounting-analyzer.md) | Reward distribution and staking: double claiming, lost rewards on unstake, reward dilution, rate manipulation, accumulator overflow, and interest accrual. |
| [lock-funds-analyzer.md](../../agents/lock-funds-analyzer.md) | Stuck/locked funds: missing withdrawal paths, ETH stuck in contract, missing emergency withdraw, blacklisted address funds, and rounding dust. |
| [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) | Fee logic security: fee bypass vectors, double charges, missing collection, incorrect distribution, timing manipulation, and denominator mismatches. |
| [eth-native-handler-analyzer.md](../../agents/eth-native-handler-analyzer.md) | ETH/native token handling: msg.value reuse in multicall, missing refunds, forced ETH via selfdestruct, WETH wrap/unwrap, and failed transfer blocking. |
| [state-management-analyzer.md](../../agents/state-management-analyzer.md) | State consistency: stale state after external calls, missing updates, storage deletion orphans, cross-contract desync, array/mapping corruption, cache invalidation, and pause mechanism gaps. |
| [data-validation-analyzer.md](../../agents/data-validation-analyzer.md) | Input validation: zero-address checks, unchecked return values, off-by-one errors, ABI encoding issues, bounds validation, decimal handling, unsafe type casting, and encodePacked hash collisions. |
| [amm-dex-analyzer.md](../../agents/amm-dex-analyzer.md) | AMM/DEX security: pool initialization, swap slippage, liquidity manipulation, concentrated liquidity ticks, fee collection, routing validation, Uniswap V4 hooks, and LP token valuation. |
| [perpetual-derivatives-analyzer.md](../../agents/perpetual-derivatives-analyzer.md) | Perpetual/derivatives security: funding rate accrual, margin calculations, open interest tracking, PnL settlement, order execution, mark price manipulation, ADL, and options settlement. |
| [liquid-staking-restaking-analyzer.md](../../agents/liquid-staking-restaking-analyzer.md) | Liquid staking and restaking security: withdrawal queue manipulation, validator lifecycle, operator/AVS delegation, slashing accounting, exchange rate protection, beacon chain proofs, and multi-LST vault composition. |
| [vesting-streaming-analyzer.md](../../agents/vesting-streaming-analyzer.md) | Vesting and streaming security: release rate math, claim drainage, vesting transfers, cliff bypass, revocation accounting, stream cancellation, rebasing token vesting, and migration formula errors. |
| [auction-mechanism-analyzer.md](../../agents/auction-mechanism-analyzer.md) | Auction mechanism security: Dutch auction price decay, zero-amount purchases, bid cancellation/sniping, settlement errors, bidder griefing, escrow management, collateral auctions, and reserve price enforcement. |

### Step 3 — Orchestration of security checks
Spawn the selected ( only the strictly selected, not all of them ) subagents from Step 2 and let them perform their security checklists. Their task is to validate if there are any exploits based on their individiaul checklists and build a vulnerability report list. Respect command parameter `--subagents-model`.

### Step 4 — Vulnerabilities classification
1. Use the following example as a guide to know how to classify the issues found in the vulnerability report list:
    - Info — e.g. code cleanup; gas cost optimization; missing comments on crucial logic; typos, etc. ( no real impact on contracts funds )
    - Low — e.g. missing events; floating pragma; zero address validations inside the constructor; anything that an user can enter as parameter and eventually damage only himself, etc. ( no real impact on contracts funds )
    - Medium — e.g. impactful issues, but extremely rare to happen; centralization risks; risks done by trusted role by the time of deployment or setter method; DOS without real impact on user or protocol funds ( no real impact or very low impact on funds )
    - High — e.g. oracle manipulations; funds being locked due to DOS; access control; attacks of stealing or locking user or protocol funds, but requiring significant amount of capital ( impact on contracts funds, but under set of conditions — no direct theft or lockup of funds )
    - Critical — in general аttacks that bring to the protocol’s end ( wide open impact on users or protocol funds meaning that the majority of funds can be directly stolen or locked )
2. Take into account command parameter `--raw-manual-context`. E.g. `--raw-manual-context "protocol won't use erc777 tokens"` shall exclude any erc777 vulnerability reports. Skip if parameter not passed.
3. Order the issues by impact — Critical is first, High is after critical, etc.

### Step 5 — Unbiased results check
Spawn the [unbiased-analyzer.md](./references/local-agents/unbiased-analyzer.md) subagent. Based on different criterias his job is to exclude vulnerabilities from the report list or downgrade their severity.

### Step 6 — Output report
1. Output the final clean vulnerability report list in a bordered table with the following structure:
    | Severity | Contract | Line(s) | Subagent | Summary | Impact | Recommendation |
    |:-------:|:-------:|:-------:|:-------:|:-------:|:-------:|:-------:|
2. Take into account if command parameter `--report-output` has been applied.
