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
- `--raw-manual-context <context>`: This is anything that you would like to add as additional context about the particular codebase. e.g. `/smart-contract-analyzer StakingPool.sol --raw-manual-context "protocol won't use rebase tokens"`. 
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project `analyzer-report-<protocol_slug>.md`.

## Instructions
### Step 1 — Crawling
At this step crawl the protocol smart contract(s):
- if the target is a particular `.sol` contract then focus entirely on that specific contract plus all the imported/inherited smart contract
- if the target is a particular folder then crawl all the `.sol` contracts in this folder and children folders

By crawling I mean scan the codebase, because based on the scan result you will decide which subagents to include in the Orchestration. You need to have clear idea about each smart contract and it's logic & modules to be precise in the Orchestration routing step. 

**Out of scope**: skip crawling folders such as `interfaces/`, `mock/`, `mocks/`, `test/`, `tests/` and smart contract file with following pattern `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

### Step 2 — Orchestration routing
1. Take into account if command parameter `--exclude-subagents` has been applied — the selected subagents marked as excluded are out of scope. 
2. Now based on the crawling report from Step 1, decide which in scope subagents should be spawned — be super precise with this decision. Example:
    - A codebase that doesn't include upgradeable smart contracts pattern doesn't have to be analyzed by the [upgrade-proxy-analyzer.md](../../agents/upgrade-proxy-analyzer.md) subagent
    - A codebase that doesn't rely on oracle dependency ( the protocol is not request price feeds data from Chainlink, Pyth, etc. ) doesn't have to be analyzed by the [oracle-analyzer.md](../../agents/oracle-analyzer.md)
    - A codebase that doesn't include fee logic such as charging fees or fee collections doesn't have to be analyzed by the [fee-accounting-analyzer.md](../../agents/fee-accounting-analyzer.md) subagent
    - etc, etc.

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

### Step 3 — Orchestration of security checks
Spawn the selected ( only the strictly selected, not all of them ) subagents from Step 2 and let them perform their security checklists. Their task is to validate if there are any exploits based on their individiaul checklists and build a vulnerability report list. Respect command parameter `--subagents-model`.

### Step 4 — Vulnerabilities classification
1. Use the following example as a guide to know how to classify the issues found in the vulnerability report list:
    - Info — e.g. code cleanup; gas cost optimization; missing comments on crucial logic; typos, etc. ( no real impact on contracts funds )
    - Low — e.g. missing events; floating pragma; zero address validations inside the constructor; anything that an user can enter as parameter and eventually damage only himself, etc. ( no real impact on contracts funds )
    - Medium — e.g. impactful issues, but extremely rare to happen; centralization risks; risks done by trusted role by the time of deployment or setter method; DOS without real impact on user or protocol funds ( no real impact or very low impact on funds )
    - High — e.g. oracle manipulations; funds being locked due to DOS; access control; attacks of stealing or locking user or protocol funds, but requiring significant amount of capital ( impact on contracts funds, but under set of conditions — no direct theft or lockup of funds )
    - Critical — in general аttacks that bring to the protocol’s end ( wide open impact on users or protocol funds meaning that the majority of funds can be directly stolen or locked )
2. Remove the duplicates.
3. Take into account terminal parameter `--raw-manual-context`. E.g. `--raw-manual-context "protocol won't use erc777 tokens"` shall exclude any erc777 vulnerability reports. Skip if parameter not passed.
4. Order the issues by impact — Critical is first, High is after critical, etc.

### Step 5 — Unbiased results check
Spawn the [unbiased-analyzer.md](./references/local-agents/unbiased-analyzer.md) subagent. Based on different criterias his job is to exclude vulnerabilities from the report list or downgrade their severity.

### Step 6 — Output report
1. Output the final clean vulnerability report list in a bordered table with the following structure:
    | Severity | Contract | Line(s) | Subagent | Description |
    |:-------:|:-------:|:-------:|:-------:|:-------:|
2. Take into account if command parameter `--report-output` has been applied.
