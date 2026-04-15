# Solidity Claude Code Setup

## Purpose

The following repo provides Claude Code skills purpose-built for Solidity security auditing and protocol research. The [smart-contract-analyzer](.claude/skills/smart-contract-analyzer/) skill crawls a codebase, intelligently selects which of its 27 specialized subagents are relevant to the code _(covering attack surfaces from reentrancy and flash loans to oracle manipulation and proxy upgrades)_, runs them in parallel, and produces a severity-classified vulnerability report with built-in false-positive filtering. The [solidity-protocol-context](.claude/skills/solidity-protocol-context/) skill reverse-engineers a protocol's architecture into structured context — actors, entry points, fund flows, fee collection logic, access control diagrams, and dependency maps. Both skills can be triggered automatically by the agent or invoked directly by terminal command, example:
```
/smart-contract-analyzer contracts/
```


## Available Claude Code Skills:

| Skill title | Description |
|----------------|-------------|
| [smart-contract-analyzer](.claude/skills/smart-contract-analyzer/) | Parallel security audit across [27 specialized subagents](.claude/agents/), each one responsible for different groups of attack vectors |
| [solidity-protocol-context](.claude/skills/solidity-protocol-context/) | Protocol-level context extraction with diagrams and flow analysis |

## Prerequisites

- [Claude Code CLI](https://code.claude.com/docs)

## Installation

- Global install _(skill available in all projects)_:
    ```
    mkdir -p ~/.claude/skills/smart-contract-analyzer && cp -R .claude/skills/smart-contract-analyzer/SKILL.md ~/.claude/skills/smart-contract-analyzer && mkdir -p ~/.claude/agents && cp .claude/agents/* ~/.claude/agents
    ```

- Project-only install:
    - Place the skill under `.claude/skills/` and the subagents under `.claude/agents/` at the root of your project. This way the skill will only activate for prompts within the scope of that project.

## License

This repository is released under the [MIT License](LICENSE).