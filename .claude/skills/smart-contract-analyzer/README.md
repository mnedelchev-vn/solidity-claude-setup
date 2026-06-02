# Smart contract analyzer skill

The purpose of this skill is to crawl a smart contract(s) and spot security issues. The skill is currently spawning 32 unique subagents _( Orchestration )_ covering 786 checklist cases across different groups of attack vectors:
| Subagent | Cases covered | Description |
|----------------|:---:|-------------|
| [math-analyzer.md](../../agents/math-analyzer.md) | 38 | Solidity does not support float type which leads to a lot of issues with division and rounding and this subagent aims to spot them. |
| [signature-verification-analyzer.md](../../agents/signature-verification-analyzer.md) | 30 | Covering different attack vectors with signatures on-chain verification such as signature replay, DoS, etc. |
| [oracle-analyzer.md](../../agents/oracle-analyzer.md) | 46 | Covering Chainlink's and Pyth's potential issues during integration and fetching of price feed data. |
| [reentrancy-analyzer.md](../../agents/reentrancy-analyzer.md) | 19 | All forms of reentrancy: single-function, cross-function, cross-contract, read-only, and ERC token callback reentrancy (ERC721/ERC777/ERC1155). |
| [access-control-analyzer.md](../../agents/access-control-analyzer.md) | 23 | Missing or broken access control, unauthorized function calls, unprotected initializers, privilege escalation, and RBAC misconfigurations. |
| [centralization-privilege-analyzer.md](../../agents/centralization-privilege-analyzer.md) | 24 | Centralization and trusted-role risk: arbitrary parameter changes, unbounded fee/rate/mint powers, direct access to user funds, address re-pointing, single points of failure, and missing timelocks or bounds on privileged actions. |
| [liquidation-analyzer.md](../../agents/liquidation-analyzer.md) | 28 | Liquidation mechanism security in lending protocols, perpetuals, CDPs: blocked liquidations, bad debt, self-liquidation, and incentive manipulation. |
| [lending-protocol-analyzer.md](../../agents/lending-protocol-analyzer.md) | 25 | Lending/borrowing mechanics: interest accrual ordering, rate model errors, debt index accounting, borrow/repay bugs, supply/borrow cap bypass, health factor gaps, and reserve fee accounting. |
| [dos-analyzer.md](../../agents/dos-analyzer.md) | 28 | Denial-of-service vectors: unbounded loops, gas griefing, block gas limit issues, external call failures, state bloat, and blacklist blocking. |
| [frontrunning-analyzer.md](../../agents/frontrunning-analyzer.md) | 27 | Front-running attacks, sandwich attacks, MEV extraction, slippage protection issues, missing deadlines, oracle update front-running, commit-reveal schemes, and VRF manipulation. |
| [cross-chain-analyzer.md](../../agents/cross-chain-analyzer.md) | 28 | Cross-chain messaging, token bridges, L2 interactions: message replay, source validation, failed message handling, sequencer downtime, decimal mismatches. |
| [nft-marketplace-analyzer.md](../../agents/nft-marketplace-analyzer.md) | 23 | NFT (ERC721/ERC1155) security: unsafe mints, token ID manipulation, approval issues, royalty bypass, callback reentrancy, and position NFT lifecycle. |
| [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) | 23 | Upgradeable contract security: re-initializable contracts, storage collisions, layout changes, uninitialized implementations, and selfdestruct risks. |
| [flashloan-analyzer.md](../../agents/flashloan-analyzer.md) | 17 | Flash loan attack vectors: price manipulation, governance attacks, flash mint exploits, fee bypass, callback safety, and invariant violations. |
| [token-compatibility-analyzer.md](../../agents/token-compatibility-analyzer.md) | 26 | ERC20 edge cases: fee-on-transfer, rebasing, ERC777 hooks, non-standard returns (USDT), blacklistable tokens, approval race conditions, and pausable tokens. |
| [governance-analyzer.md](../../agents/governance-analyzer.md) | 24 | Governance and voting security: flash loan voting, double voting, proposal griefing, delegation manipulation, quorum bypass, and timelock issues. |
| [donation-attack-analyzer.md](../../agents/donation-attack-analyzer.md) | 17 | Share inflation and donation attacks: first-depositor exploits, ERC4626 inflation, exchange rate manipulation, and dead shares/virtual offset protection. |
| [vault-share-accounting-analyzer.md](../../agents/vault-share-accounting-analyzer.md) | 24 | ERC4626 and custom vault share accounting: totalAssets/share-price correctness, convertTo/preview rounding direction, deposit/withdraw share math, exchange-rate manipulation, and pause/cap/cooldown edge cases. |
| [reward-accounting-analyzer.md](../../agents/reward-accounting-analyzer.md) | 22 | Reward distribution and staking: double claiming, lost rewards on unstake, reward dilution, rate manipulation, accumulator overflow, and interest accrual. |
| [merkle-airdrop-claims-analyzer.md](../../agents/merkle-airdrop-claims-analyzer.md) | 19 | Merkle-proof airdrops and claims: double claims, proof replay across roots/chains, missing leaf binding, zero/uninitialized roots, root-update handling, and unclaimed-fund recovery. |
| [lock-funds-analyzer.md](../../agents/lock-funds-analyzer.md) | 24 | Stuck/locked funds: missing withdrawal paths, ETH stuck in contract, missing emergency withdraw, blacklisted address funds, and rounding dust. |
| [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) | 21 | Fee logic security: fee bypass vectors, double charges, missing collection, incorrect distribution, timing manipulation, and denominator mismatches. |
| [eth-native-handler-analyzer.md](../../agents/eth-native-handler-analyzer.md) | 20 | ETH/native token handling: msg.value reuse in multicall, missing refunds, forced ETH via selfdestruct, WETH wrap/unwrap, and failed transfer blocking. |
| [state-management-analyzer.md](../../agents/state-management-analyzer.md) | 21 | State consistency: stale state after external calls, missing updates, storage deletion orphans, cross-contract desync, array/mapping corruption, cache invalidation, and pause mechanism gaps. |
| [data-validation-analyzer.md](../../agents/data-validation-analyzer.md) | 24 | Input validation: zero-address checks, unchecked return values, off-by-one errors, ABI encoding issues, bounds validation, decimal handling, unsafe type casting, and encodePacked hash collisions. |
| [timestamp-time-dependence-analyzer.md](../../agents/timestamp-time-dependence-analyzer.md) | 20 | Timestamp and time-dependence: block.timestamp/block.number reliance, hardcoded block-time assumptions across chains, epoch/boundary math, deadlines, cooldowns, and accrual-interval errors. |
| [amm-dex-analyzer.md](../../agents/amm-dex-analyzer.md) | 27 | AMM/DEX security: pool initialization, swap slippage, liquidity manipulation, concentrated liquidity ticks, fee collection, routing validation, Uniswap V4 hooks, and LP token valuation. |
| [perpetual-derivatives-analyzer.md](../../agents/perpetual-derivatives-analyzer.md) | 25 | Perpetual/derivatives security: funding rate accrual, margin calculations, open interest tracking, PnL settlement, order execution, mark price manipulation, ADL, and options settlement. |
| [liquid-staking-restaking-analyzer.md](../../agents/liquid-staking-restaking-analyzer.md) | 25 | Liquid staking and restaking security: withdrawal queue manipulation, validator lifecycle, operator/AVS delegation, slashing accounting, exchange rate protection, beacon chain proofs, and multi-LST vault composition. |
| [withdrawal-queue-redemption-analyzer.md](../../agents/withdrawal-queue-redemption-analyzer.md) | 22 | Withdrawal queues and redemptions: queue/epoch accounting, request ordering, claim-at-wrong-price, partial fulfillment, queue griefing/DoS, and stuck redemption requests. |
| [vesting-streaming-analyzer.md](../../agents/vesting-streaming-analyzer.md) | 23 | Vesting and streaming security: release rate math, claim drainage, vesting transfers, cliff bypass, revocation accounting, stream cancellation, rebasing token vesting, and migration formula errors. |
| [auction-mechanism-analyzer.md](../../agents/auction-mechanism-analyzer.md) | 23 | Auction mechanism security: Dutch auction price decay, zero-amount purchases, bid cancellation/sniping, settlement errors, bidder griefing, escrow management, collateral auctions, and reserve price enforcement. |

The skill decides which subagent is to be called per codebase:
- A codebase that doesn't include upgradeable smart contracts pattern doesn't have to be analyzed by the [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) subagent
- A codebase that doesn't rely on oracle dependency ( the protocol is not request price feeds data from Chainlink, Pyth, etc. ) doesn't have to be analyzed by the [oracle-analyzer.md](../../agents/oracle-analyzer.md)
- A codebase that doesn't include fee logic such as charging fees or fee collections doesn't have to be analyzed by the [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) subagent
- etc, etc.

Each subagent has explicitly defined allowed tools — `tools: Glob, Grep, Read, Bash` _( read-only )_. Access to `Write` or `Edit` tools is denided.

After the selected subagents are done analyzing there is one more subagent left to be spawned — [classification-analyzer.md](./references/local-agents/classification-analyzer.md) subagent. This subagent double check the issues collected in the vulnerabilities report list by validating if the defined severity/impact is correct. Based on preconditions the subagent can decide to:
- remove duplicates if such are spotted _(often two separate impacts on a protocol have the same root cause)_
- drop issues vulnerabilities report list if they're invalid
- or to downgrade them if the initial classification is wrong

## Installation

```
mkdir -p ~/.claude/skills/smart-contract-analyzer && cp .claude/skills/smart-contract-analyzer/SKILL.md ~/.claude/skills/smart-contract-analyzer && cp -R .claude/skills/smart-contract-analyzer/references ~/.claude/skills/smart-contract-analyzer && mkdir -p ~/.claude/agents && cp .claude/agents/* ~/.claude/agents
```

## Skill parameters:

- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--raw-manual-context <context>`: This is anything that you would like to add as additional context about the particular codebase. e.g. `/smart-contract-analyzer StakingPool.sol --raw-manual-context "protocol won't use rebase tokens"`. 
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.

Trigger the skill directly with the following terminal command:
```
/smart-contract-analyzer contracts/ --report-output
```

## Execution time

The skill was triggered numerous on the Sherlock's [Clear Macro by Superfluid contest](https://audits.sherlock.xyz/contests/1263?filter=scope) and the results show that analyzing ~400 nSLOC takes roughly 6 minutes. Analyzing bigger scope with more lines of code or in general running the skill on more complex codebase will definitely increase the execution time.

## Advices

1. By default agent's response is non deterministic meaning that same user prompt being sent multitple times doesn't necessarily mean that the response will be the same. Run the analyzer at least 3 times to get a compherensive report.
2. Tight scope — run the skill on not more than 5 to 10 smart contracts. Smaller and tighten scope means that each subagent will perform with cleaner context thus leading to better results.
3. Providing manual context:
    - Manually adding parameter `--exclude-subagents` to the trigger command will offload the skill with the decision making in the orchestration routing
    - Manually adding parameter `--raw-manual-context` will also help the subagents orchestration routing e.g. `/smart-contract-analyzer StakingPool.sol --raw-manual-context "protocol won't use rebase tokens"` will helo for cleaner report output

> [!WARNING]
> Each subagent spawned by this skill provides a solid base ground checklist for the particular area of attack vectors, but it's imperfect! Every month in the web3 world we witness different and more complex varieties of web3 vulnerabilities which means that it's impossible to collect all attack vectors at one place. Updating the subagent's checklists with more and more attack vectors is a never ending process. Treat this skill as a helper and a tool, rather than fully delegating your work on it.