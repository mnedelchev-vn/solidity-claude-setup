# Solidity protocol context skill

Everything works better by following a predefined pattern and rules. Being a web3 Solidity builder or an auditor involves studying of new protocols on a weekly basis and in the constant studying it's very likely that we miss to understand something from the beginning. Some codebases are written clear with proper comments, but some of them are confusing and hard to understand from the first touch. This skill defines a set of customized rules to be followed when the research of a protocol is being performed. The end goal is that after using the skill the builder or the auditor has a clear picture of the particular protocol.

The purpose of this skill is to crawl a Solidity protocol codebase and provide a two tier context knowledge about — High level and In-depht level:
- **High level** is the programmer's first encounter with the particular protocol. The goal here is not distract with all the internal and complex modules, but:
    - to get the basic idea and type of the protocol
    - see who are the roles in the protocol - depositors, treasury managers, etc.
    - to get a list of all of the entry points to the protocol such as public and external methods, perform a symmetry check to connect all mirror methods — `deposit` & `withdraw`; `stake` & `unstake`; etc.
- **In-depth level** — after we got the core idea this is the next step and now we can move on into the details of the particular protocol such as:
    - now that we know who are the roles in the protocol here we will get a list of their access control methods per role
    - diagrams that tracks all the funds being transferred in and out to the protocol
    - diagrams including all the complex internal modules and 3rd party dependencies


## Skill parameters:

- `--skip-high-level`: Skips the High level report output and head directly to the In-depth level report
- `--skip-in-depth-level`: Skips the In-depth level report
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.
- `--docs-url <url>`: When provided, fetch the content at `<url>` using the WebFetch tool before analyzing any contracts. Could be a documentation url or just a github repo url with proper readmes providing information about the protocol. Use the fetched documentation as additional context throughout the analysis — reference it when explaining protocol-specific concepts, naming conventions, or architectural decisions found in the code.

## Installation

```
mkdir -p ~/.claude/skills/solidity-protocol-context && cp -R .claude/skills/solidity-protocol-context/SKILL.md ~/.claude/skills/solidity-protocol-context
```