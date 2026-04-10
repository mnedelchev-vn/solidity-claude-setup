# Smart contract analyzer skill

The purpose of this skill is to crawl a smart contract(s) and spot security issues. The skill is currently spawning 3 unique subagents _( Orchestration )_ and each one of them is covering different group of attack vectors:
| Subagent | Description |
|----------------|-------------|
| [math-analyzer.md](../../agents/math-analyzer.md) | Solidity does not support float type which leads to a lot of issues with division and rounding and this subagents aims to spot them. |
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