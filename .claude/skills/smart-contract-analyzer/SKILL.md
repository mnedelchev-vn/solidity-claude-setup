---
name: smart-contract-analyzer
description: This skill helps Solidity developers, auditors or security researchers to find vulnerabilities inside a Solidity smart contract(s). The skill should be used when the user prompt is pointing to a specific codebase and seeking to find security issues or exploits inside the logic. The skill has its own checklists of different group with attack vectors to be verified on a codebase.
license: MIT License
metadata:
    author: https://x.com/mnedelchev_
    version: "1.0"
---

# Smart contract analyzer
You're a Solidity smart contract analyzer. Your job is to crawl a folder with one or multiple Solidity smart contracts and then apply security checks with the help of subagents.

## Modes
All of the terminal arguments listed below are off by default.
- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project `analyzer-report-<protocol_slug>.md`.

## Instructions
### Step 1 — Crawling
At this step crawl the protocol smart contract(s):
- if the target is a particular `.sol` contract then focus entirely on that specific contract plus all the imported/inherited smart contract
- if the target is a particular folder then crawl all the `.sol` contracts in this folder and children folders

By crawling I mean scan the codebase, because based on the scan result you will decide which subagents to include in the Orchestration.

**Out of scope**: skip crawling folders such as `interfaces/`, `mock/`, `mocks/`, `test/`, `tests/` and smart contract file with following pattern `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

### Step 2 — Orchestration routing
First take into account if command parameter `--exclude-subagents` has been applied and exclude the selected subagents.

Now based on the crawling report, decide which subagents should be spawned ( only agents that are not excluded ):
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

### Step 3 — Orchestration of security checks
Spawn the selected subagents from Step 2 and let them perform their security checklists. Respect command parameter `--subagents-model`.

### Step 4 — Classification & output report
1. Use the following example as a guide to know how to classify the issues found:
    - Info — e.g. code cleanup; gas cost optimization; missing comments on crucial logic; typos, etc. ( no real impact on contracts funds )
    - Low — e.g. missing events; floating pragma; zero address validations inside the constructor; anything that an user can enter as parameter and eventually damage only himself, etc. ( no real impact on contracts funds )
    - Medium — e.g. impactful issues, but extremely rare to happen; centralization risks; risks done by trusted role by the time of deployment or setter method; DOS without real impact on user or protocol funds ( no real impact or very low impact on funds )
    - High — e.g. oracle manipulations; funds being locked due to DOS; access control; attacks of stealing or locking user or protocol funds, but requiring significant amount of capital ( impact on contracts funds, but under set of conditions — no direct theft or lockup of funds )
    - Critical — in general аttacks that bring to the protocol’s end ( wide open impact on users or protocol funds meaning that the majority of funds can be directly stolen or locked )
2. Remove duplicates.
3. Before outputting the final table, perform a quick manual check on every Critical, High and Medium findings — read the cited lines and confirm the claim holds. Read any referenced interface files and trace external calls to their concrete implementations before concluding on behavior. In simple words check if the list includes assumptions or real issues.
4. Output the final report in the following table with columns:
    | Severity | Contract | Line(s) | Subagent | Description |
    |:-------:|:-------:|:-------:|:-------:|:-------:|
5. Take into account if command parameter `--exclude-subagents` has been applied.