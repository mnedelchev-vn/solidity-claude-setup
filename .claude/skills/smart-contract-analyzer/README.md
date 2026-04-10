# Smart contract analyzer skill

The purpose of this skill is to crawl a smart contract(s) and spot security issues. The skill is currently spawning 21 unique subagents _( Orchestration )_ and each one of them is covering different group of attack vectors:
| Subagent | Description |
|----------------|-------------|
| [math-analyzer.md](../../agents/math-analyzer.md) | Solidity does not support float type which leads to a lot of issues with division and rounding and this subagent aims to spot them. |
| [signature-verification-analyzer.md](../../agents/signature-verification-analyzer.md) | Covering different attack vectors with signatures on-chain verification such as signature replay, DoS, etc. |
| [oracle-analyzer.md](../../agents/oracle-analyzer.md) | Covering Chainlink's and Pyth's potential issues during integration and fetching of price feed data. |
| [access-control-analyzer.md](../../agents/access-control-analyzer.md) | Detects missing or broken access control: unprotected initializers, missing modifiers, privilege escalation, delegatecall abuse, and input validation gaps. |
| [cross-chain-analyzer.md](../../agents/cross-chain-analyzer.md) | Audits cross-chain messaging and bridge logic for message replay, missing source validation, payload encoding issues, and L2 sequencer dependencies. |
| [dos-analyzer.md](../../agents/dos-analyzer.md) | Identifies denial-of-service vectors: unbounded loops, gas griefing, dust attacks, return bombs, and external call failures blocking execution. |
| [donation-attack-analyzer.md](../../agents/donation-attack-analyzer.md) | Detects vault share inflation and donation attacks: first-depositor exploits, exchange rate manipulation, and ERC4626 totalAssets mismatches. |
| [flashloan-analyzer.md](../../agents/flashloan-analyzer.md) | Finds flash loan attack vectors: spot price manipulation, governance attacks, collateral manipulation, and missing flash loan fee enforcement. |
| [frontrunning-analyzer.md](../../agents/frontrunning-analyzer.md) | Spots front-running and MEV vulnerabilities: missing slippage protection, missing deadlines, sandwich attacks, and permit front-running. |
| [governance-analyzer.md](../../agents/governance-analyzer.md) | Audits governance and voting mechanisms for flash loan voting, double voting via delegation, quorum manipulation, and timelock bypass. |
| [reentrancy-analyzer.md](../../agents/reentrancy-analyzer.md) | Detects all reentrancy variants: single-function, cross-function, cross-contract, read-only, and ERC721/ERC777/ERC1155 callback reentrancy. |
| [lock-funds-analyzer.md](../../agents/lock-funds-analyzer.md) | Finds scenarios where funds become permanently stuck: missing withdrawal paths, vesting errors, blocked exits, and native token handling mismatches. |
| [token-compatibility-analyzer.md](../../agents/token-compatibility-analyzer.md) | Checks ERC20 edge cases: fee-on-transfer, rebasing tokens, ERC777 hooks, blacklistable tokens, non-standard return values, and approve race conditions. |
| [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) | Audits upgradeable contracts and proxy patterns for storage collisions, unprotected implementations, UUPS auth issues, and Diamond selector clashes. |
| [liquidation-analyzer.md](../../agents/liquidation-analyzer.md) | Reviews liquidation logic for blocked liquidations, incorrect health factors, self-liquidation exploits, bad debt handling, and cascade risks. |
| [reward-accounting-analyzer.md](../../agents/reward-accounting-analyzer.md) | Detects reward distribution and accounting bugs: stale accumulators, double counting, interest rate errors, and fee accrual timing manipulation. |
| [eth-native-handler-analyzer.md](../../agents/eth-native-handler-analyzer.md) | Audits native ETH handling: msg.value reuse in loops/multicall, excess ETH not refunded, missing receive(), WETH wrap/unwrap mismatches, and force-send balance manipulation. |
| [data-validation-analyzer.md](../../agents/data-validation-analyzer.md) | Detects missing input validation: zero-address/amount checks, unchecked return values, off-by-one errors, abi.encodePacked collisions, and incorrect ABI decoding. |
| [state-management-analyzer.md](../../agents/state-management-analyzer.md) | Finds state consistency bugs: missing CEI pattern, inconsistent related variable updates, stale cached values, storage cleanup issues, and cross-contract state desynchronization. |
| [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) | Audits fee logic: fee bypass via alternative code paths, incorrect fee base amounts, double-fee charging, missing fee collection, and management/performance fee timing manipulation. |
| [nft-marketplace-analyzer.md](../../agents/nft-marketplace-analyzer.md) | Reviews NFT and marketplace security: ERC721/ERC1155 compliance, unsafe minting, position accounting on transfer, royalty bypass, metadata manipulation, and NFT-gated access bypass. |

The skill decides which subagent is to be called per codebase:
- A codebase that doesn't include upgradeable smart contracts pattern doesn't have to be analyzed by the [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) subagent
- A codebase that doesn't rely on oracle dependency ( the protocol is not request price feeds data from Chainlink, Pyth, etc. ) doesn't have to be analyzed by the [oracle-analyzer.md](../../agents/oracle-analyzer.md)
- A codebase that doesn't include fee logic such as charging fees or fee collections doesn't have to be analyzed by the [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) subagent
- etc, etc.

After the selected subagents are done analyzing there is one more subagent left to be spawned — [unbiased-analyzer.md](./references/local-agents/unbiased-analyzer.md) subagent. This subagent double check the issues collected in the vulnerabilities report list by validating them if they're really legit or if the defined severity/impact is correct. Based on some preconditions the subagent can decide to drop issues vulnerabilities report list or to downgrade them.

## Skill parameters:

- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.

Trigger the skill directly with the following terminal command:
```
/smart-contract-analyzer contracts/ --report-output
```

## Installation

```
mkdir -p ~/.claude/skills/smart-contract-analyzer && cp -R .claude/skills/smart-contract-analyzer/SKILL.md ~/.claude/skills/smart-contract-analyzer && mkdir -p ~/.claude/agents && cp .claude/agents/* ~/.claude/agents
```

## Advices

1. By default agent's response is non deterministic meaning that same user prompt being sent multitple times doesn't necessarily mean that the response will be the same. Run the analyzer at least 3 times to get a compherensive report.
2. Tight scope — run the skill on not more than 5 to 10 smart contracts. Smaller and tighten scope means that each subagent will perform with cleaner context thus leading to better results.

> [!WARNING]
> Each subagent spawned by this skill provides a solid base ground checklist for the particular area of attack vectors, but it's imperfect! Every month in the web3 world we witness different and more complex varieties of web3 vulnerabilities which means that it's impossible to collect all attack vectors at one place. Updating the subagent's checklists with more and more attack vectors is a never ending process. Treat this skill as a helper and a tool, rather than fully delegating your work on it.