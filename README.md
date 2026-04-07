# Solidity Claude Code Setup

## Purpose

The following repo aims to support Web3 builders or security researches when researching or breaking Solidity protocols with the help of Claude Code skills. Skills are intended not to limit the main agent's performance, but rather to sharpen its focus on specific parts of the web3 protocols. They could be called on demand when the main agent decides to active them or they could be explicitly called directly by terminal command.

## Available Skills:

| Skill title | Description |
|----------------|-------------|
| [smart-contract-analyzer](skills/smart-contract-analyzer/) | Smart contract security analyzer spawning multiple subagents in parallel thus performing security checks on different attack vectors |
| [solidity-protocol-context](skills/solidity-protocol-context/) | Crawling unknown Solidity protocol and providing High level and In-depth level context about the codebase |

### Smart contract analyzer skill

The purpose of this skill is to crawl a smart contract(s) and spot security issues. The skill is currently spawning 3 unique subagents _( Orchestration )_ and each one of them is covering different group of attack vectors:
1. [math-analyzer.md](agents/math-analyzer.md) — Solidity does not support float type which leads to a lot of issues with division and rounding and this subagents aims to spot them.
2. [signature-verification-analyzer.md](agents/signature-verification-analyzer.md) — Covering different attack vectors with signatures on-chain verification such as signature replay, DoS, etc.
3. [oracle-analyzer.md](agents/oracle-analyzer.md) — Covering Chainlink's and Pyth's potential issues during integration and fetching of price feed data.

#### Skill parameters:
- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.

> [!WARNING]
> Each subagent spawned by this skill provides a solid base ground checklist for the particular area of attack vectors, but it's imperfect! Every month in the web3 world we witness different and more complex varieties of web3 vulnerabilities which means that it's impossible to collect all attack vectors at one place. Updating the subagent's checklists with more and more attack vectors is a never ending process. Treat this skill as a helper and a tool, rather than fully delegating your work on it.

### Solidity protocol context skill

The purpose of this skill is to crawl a Solidity protocol codebase and provide a two tier context knowledge about — High level and In-depht level:
- **High level** is the programmer's first encounter with the particular protocol. The goal here is not distract with all the internal and complex modules, but:
    - to get the basic idea of the protocol.
    - see who are the roles in the protocol - depositors, treasury managers, etc.
    - to get a list of all of the entry points to the protocol such as public and external methods, perform a symmetry check of mirror methods — `deposit` & `withdraw`; `stake` & `unstake`; etc.
- **In-depth level** — after we got the core idea idea of the particular protocol and we can move on into the details of it such as:
    - now that we know who are the roles in the protocol here we will get a list of their access control list of methods
    - diagrams that tracks all the funds being transferred in and out to the protocol
    - diagrams including all the complex internal modules and 3rd party dependencies


#### Skill parameters:
- `--skip-high-level`: Skips the High level report output and head directly to the In-depth level report
- `--skip-in-depth-level`: Skips the In-depth level report
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.
- `--docs-url <url>`: When provided, fetch the content at `<url>` using the WebFetch tool before analyzing any contracts. Could be a documentation url or just a github repo url with proper readmes providing information about the protocol. Use the fetched documentation as additional context throughout the analysis — reference it when explaining protocol-specific concepts, naming conventions, or architectural decisions found in the code.

## Installation

Copy the specific skill you want your Claude Code agent to use at your general skills folder ( `~/.claude/skills/` ) _( by doing this the skill will be taken into account by every user prompt in your Claude Code agent, however because of the uniqueness of skills the agent will only skim through the particular skill description and then decide if the skill should be used or not )_:
```
cp -R skills/solidity-protocol-context ~/.claude/skills
```
Or if you want the skill to be taken into account only for specific project or folder then create `.claude/skills/` folder at the root of your project and place the skill there. Now the skill will be active only for user prompts in that specific folder.

## License

This repository is released under the [MIT License](LICENSE).