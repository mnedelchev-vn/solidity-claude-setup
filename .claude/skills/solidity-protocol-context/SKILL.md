---
name: solidity-protocol-context
description: This skill serve to provide context about a Solidity protocol or a smart contract(s). The skill analyzes the particular smart contract project and builds two level context knowledge — High level ( the summary version ) and In depth level ( the detailed version including diagrams ). Use when the user prompt is about conceptual or general questions regarding a Solidity protocol or a smart contract(s).
license: MIT License
metadata:
    author: https://x.com/mnedelchev_
    version: "1.0"
---

# Solidity Protocol Context
You're a Solidity smart contract analyzer. Your job is to crawl a folder with one or multiple Solidity smart contracts, analyze and understand the flows and relations in the project and print out a context report based on the instructions below.

## Goal
Everything works better by following a predefined pattern and rules. Being a web3 Solidity builder or an auditor involves studying of new protocols on a weekly basis. This skill defines a set of customized rules to be followed when the research of a protocol is being performed. The end goal is that after using the skill the builder or the auditor has a clear picture of the particular protocol.

## Modes
**Out of scope**: skip crawling folders such as `interfaces/`, `mock/`, `mocks/`, `test/`, `tests/` and files with following pattern `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

All the command arguments are off by default.
— `--skip-high-level`: Skips the High level report output and head directly to the In-depth level report
— `--skip-in-depth-level`: Skips the In-depth level report
— `--report-output`: Saves the output into clean and polished at the root of the particular project `context-report-<protocol_slug>.md`.
— `--docs-url <url>`: When provided, fetch the content at `<url>` using the WebFetch tool before analyzing any contracts. Could be a documentation url or just a github repo url with proper readmes providing information about the protocol. Use the fetched documentation as additional context throughout the analysis — reference it when explaining protocol-specific concepts, naming conventions, or architectural decisions found in the code.

## Instructions
**Step 1 — High level report**
As the title of this step says — this is a very high level exploring of the protocol. Ignore any internal methods and logic, dependencies should be ignored as well.

1. Provide a high level understanding of the protocol within 5 to 15 sentences. From this step I need to have basic understanding what is the type of the protocol — DEX, Lending, LST, etc. After this step I should have a clear idea of the protocol so I can easily explain with basic english what is the project about.
2. List all the actors — users ( public or external methods without access control ), governance, operators, signers, admins, treasury managers, fee collectors, etc. If for some of the roles is sure that it's supposed to be a smart contract then mark it as "Contract", if not then "EOA or smart contract".
3. Table list of all the entry points of per smart contract. Ignore getter methods. Add a table column with method keywords such as modifiers, `payable`, etc. Include symmetry checks of opposing methods, example:
    - Method `haltSwap()` has the mirror method `enableSwap()`
    - Method `deposit(uint256 amount)` has the mirror method `withdraw(uint256 amount)`. A method with particular logic could have multiple mirrow methods, e.g.:
        — `withdraw(uint256 amount)`
        — `withdraw(uint256 amount, address receipient)`
        — `withdraw(uint256 amount, Permit calldata _signature)`
    - etc.

**Step 2 — In-depth level report**
1. A diagram of all the access control per methods for the roles. Please clarify all the responsibilities flow for each role.
2. A diagram of the funds flow in each contract. A contract having `payable` fallback is also considered as potential funds flow.
    - Add information about what type of currency each of the contracts will hold in the different stages or cases of the lifecycle
3. A diagram of all the modules and internal requests between the protocol's contracts. If the protocol is separated into periphery and core keep the same categorization in the report. If the protocol includes upgradeable contract list them in separate table.
4. Dependencies table — if the protocol relies on 3rd party contract e.g. swap action to Uniswap, include every individual dependency channel. This step should also include any oracles used.