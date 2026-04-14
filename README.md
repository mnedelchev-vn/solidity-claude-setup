# Solidity Claude Code Setup

## Purpose

The following repo aims to support Web3 builders or security researches when researching or breaking Solidity protocols with the help of Claude Code skills. Skills are intended not to limit the main agent's performance, but rather to sharpen its focus on specific parts of the web3 protocols. Each one of the Claude Code skills have proper descriptions meaning that they could be called on demand when the main agent decides to active them or they could be explicitly called directly by terminal command, example:
```
/smart-contract-analyzer contracts/
```

## Available Claude Code Skills:

| Skill title | Description |
|----------------|-------------|
| [smart-contract-analyzer](.claude/skills/smart-contract-analyzer/) | Smart contract security analyzer spawning multiple subagents in parallel which are performing security checks on different groups of attack vectors |
| [solidity-protocol-context](.claude/skills/solidity-protocol-context/) | Crawling a Solidity protocol codebase and providing High level and In-depth level context about the logic including diagrams, funds & fees flows, etc |

## Installation

Copy the specific skill you want your Claude Code agent to use at your general skills folder ( `~/.claude/skills/` ) _( by doing this the skill will be taken into account by every user prompt in your Claude Code agent, however because of the uniqueness of skills the agent will only skim through the particular skill description and then decide if the skill should be used or not )_. The following command copies the [smart-contract-analyzer](.claude/skills/smart-contract-analyzer/) skill into your main Claude Code skills folder together with all of the skill subagents:
```
mkdir -p ~/.claude/skills/smart-contract-analyzer && cp -R .claude/skills/smart-contract-analyzer/SKILL.md ~/.claude/skills/smart-contract-analyzer && mkdir -p ~/.claude/agents && cp .claude/agents/* ~/.claude/agents
```
Or if you want the skill to be taken into account only for specific project then create `.claude/skills/` folder at the root of your project and place the skill there. Now the skill will be active only for user prompts in that specific folder.

## License

This repository is released under the [MIT License](LICENSE).