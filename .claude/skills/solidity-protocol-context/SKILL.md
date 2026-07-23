---
name: solidity-protocol-context
description: This skill serves to provide context about a Solidity protocol or a smart contract(s). The skill analyzes the particular smart contract project and builds two level context knowledge — High level ( the summary version ) and In depth level ( the detailed version including diagrams ). Use when the user prompt is about conceptual or general questions regarding a Solidity protocol or a smart contract(s).
license: MIT License
metadata:
    author: https://x.com/mnedelchev_
    version: "1.0"
---

# Solidity Protocol Context
You're a Solidity protocol analyzer. Your job is to crawl a folder with one or multiple Solidity smart contracts, analyze and understand the flows and relations in the project and print out a context report based on the instructions below.

## Goal
Everything works better by following a predefined pattern and rules. Being a web3 Solidity builder or an auditor involves studying new protocols on a weekly basis, and in the constant studying it's very likely that we fail to understand something from the beginning. Some codebases are written clearly with proper comments, but some of them are confusing and hard to understand from the first touch. This skill defines a set of customized rules to be followed when the research of a protocol is being performed. The end goal is that through using this skill the builder or the auditor has a clear picture of the particular protocol.

## Modes
All of the terminal arguments listed below are off by default.
- `--skip-high-level`: Skips the High level report output and heads directly to the In-depth level report
- `--skip-in-depth-level`: Skips the In-depth level report
- `--report-output`: Saves the output into a clean and polished report file at the root of the particular project. Both levels should be separated into two files e.g. `high-lvl-report-<protocol_slug>.md` & `in-depth-lvl-report-<protocol_slug>.md`.
- `--docs-url <url>`: When provided, fetch the content at `<url>` using the WebFetch tool before analyzing any contracts. Could be a documentation url or just a github repo url with proper readmes providing information about the protocol. Enumerate the sitemap, discover subpages and crawl the rest of the documentation tree. Use the fetched documentation as additional context throughout the analysis — reference it when explaining protocol-specific concepts, naming conventions, or architectural decisions found in the code. The scope is the entire url page and all of its subpages.

## Instructions

### Step 1 — Study the code
**Out of scope**: skip crawling folders such as `interface(s)/`, `mock(s)/`, `test(s)/` and files with following pattern `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

At this step crawl the protocol smart contract(s). If the skill has been triggered on a specific project folder then the search pattern for the smart contract(s) is `./contracts/**/*.sol` or `./src/**/*.sol`. Ignore if the skill is triggered on a particular `.sol` file.

Take your time to study the code, you need to have a clear idea of the entire logic in order to be able to export proper context reports. Do not proceed to the next step until you have studied the entire codebase.

### Step 2 — Study the specs
**Scope rules**:
- Respect the **Out of scope** defined in the previous step. You shouldn't spend time researching documentation regarding smart contract(s) which are OOS.
- Skip docs sections that describe out-of-scope components/modules, front-end behavior, or off-chain infrastructure — unless a claim there asserts something about the in-scope on-chain logic.
- If the repository has **no documentation at all** that describes protocol behavior, say so explicitly and return an empty finding list — do not invent claims.

Crawl the repository for every artifact whose purpose is to explain protocol behavior. Cast a wide net:
- **Markdown & text docs** — `README*`, `*.md`, `*.txt`, `*.rst`, and anything under `doc(s)/`, `documentation(s)/`, `spec(s)/`, `whitepaper(s)/`, `audit(s)/`, `compliance(s)/`, `wiki(s)/`.
- **Embedded NatSpec** — `@notice`, `@dev`, `@param`, `@return`, `@inheritdoc` and free-form comments inside the in-scope `.sol` files. NatSpec is documentation that lives in the code and is the most authoritative statement of intent — treat it as first-class.
- **Diagrams** — mermaid / ASCII flow diagrams that assert an ordering of calls or a state machine.

Studying the specs will complete the entire picture and fill the gap of what could not be understood just by studying the code.

### Step 3 — High level report
This is a very high-level exploration of the protocol. Ignore any internal methods requests and internal logic, requests to dependencies should be ignored as well. The key of the High level report is not to get lost in complexity. Respect parameter `--skip-high-level`.

1. Provide a high level understanding of the protocol within 5 to 15 sentences. From this step I need to have a basic understanding of what the type of the protocol is — DEX, Lending, LST, etc. After this step I should have a clear idea of the protocol so I can easily explain with basic English what is the project about.
2. Provide a high level diagram including only the top-level interactions in the protocol. Internal calls and dependencies should not be included in the diagram.
3. List all the actors — e.g. users, governance, operators, signers, admins, depositors, borrowers, liquidators, treasury managers, fee collectors, etc., all of them! If for some of the roles it's sure that it's supposed to be a smart contract then mark it as "Contract", if not then "EOA or smart contract".
4. Table list of all the entry points per smart contract ( public or external methods without access control ). `fallback` or `receive` are also treated as an entry point to a particular contract. Ignore getter methods and "helper/utils" methods that are built to serve other methods internally, example — `_computeFee`, `_calculateInterest`, etc. ( most of the times these methods are `internal` ). Add a table column with a short plain text description of each method's purpose. Add a table column with the method's keywords & modifiers — visibility ( `public`, `external`, `internal`, `private` ), Mutability ( `view`, `pure`, `payable` ), `virtual` & `override` and all the custom defined modifiers. Include symmetry checks of opposing methods, example:
    - Method `haltSwap()` has the mirror method `enableSwap()`
    - Method `deposit(uint256 amount)` has the mirror method `withdraw(uint256 amount)`. A method with particular logic could have multiple mirror methods, e.g.:
        - `withdraw(uint256 amount)`

        - `withdraw(uint256 amount, address recipient)`
        - `withdraw(uint256 amount, Permit calldata _signature)`
    - etc.

### Step 4 — In-depth level report
This report is supposed to complete the entire picture compared to the high level report. Every tiny detail matters here. Respect parameter `--skip-in-depth-level`.

1. Diagrams:
    1.1. One main diagram including the entire mind map of all actors, contracts, modules, dependencies, external and internal requests. If the protocol is separated into periphery and core keep the same categorization in the report. You can use the diagram [tare-onchain-architecture.jpg](./references/tare-onchain-architecture.jpg) as a benchmark.
    1.2. Diagrams of all the access control per methods for the roles. Separate them into two different categories — trusted & untrusted. Please clarify all the responsibilities flow for each role:
        - Provide separate list if there is a superior protocol role that manages other roles e.g. admin being able to add or remove operators
        - Specific role that manages contract upgradability, timelocks, etc.
        - Trove manager being able to operate with pool's funds
        - etc, etc.
    1.3. Separate diagrams of all the funds flows in each contract:
        - Add information about what type of tokens each of the contracts will hold in the different stages or cases of the lifecycle
        - Separated diagrams about the fee generation & collection logic
        - NFT transfers should also be treated as a funds flow
        - A contract having `payable` fallback is also considered as potential funds flow
    1.4. Zoomed-in diagram of all the internal/external modules and internal/external requests between the protocol's contracts or any other contracts. If the protocol includes upgradeable contracts, list them in a separate table.
2. Dependencies table — if the protocol relies on a 3rd party contract e.g. swap action to Uniswap or fetching prices from Chainlink — include every individual dependency channel.