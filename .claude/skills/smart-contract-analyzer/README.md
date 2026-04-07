# Smart contract analyzer skill

The purpose of this skill is to crawl a smart contract(s) and spot security issues. The skill is currently spawning 3 unique subagents _( Orchestration )_ and each one of them is covering different group of attack vectors:
1. [math-analyzer.md](../../agents/math-analyzer.md) — Solidity does not support float type which leads to a lot of issues with division and rounding and this subagents aims to spot them.
2. [signature-verification-analyzer.md](../../agents/signature-verification-analyzer.md) — Covering different attack vectors with signatures on-chain verification such as signature replay, DoS, etc.
3. [oracle-analyzer.md](../../agents/oracle-analyzer.md) — Covering Chainlink's and Pyth's potential issues during integration and fetching of price feed data.

## Skill parameters:

- `--exclude-subagents <list>`: Skip one or many security subagents from the Orchestration.
- `--subagents-model <model>`: Spawn the subagents with predefined model. Default agent is **sonnet**.
- `--report-output`: Saves the output into clean and polished report file at the root of the particular project.

## Installation

```
mkdir -p ~/.claude/skills/smart-contract-analyzer && cp -R .claude/skills/smart-contract-analyzer/SKILL.md ~/.claude/skills/smart-contract-analyzer && mkdir -p ~/.claude/agents && cp .claude/agents/* ~/.claude/agents
```

## Advices

1. By default agent's response is non deterministic meaning that same user prompt being sent multitple times doesn't necessarily mean that the response will be the same. Run the analyzer at least 3 times to get a compherensive report.
2. Tight scope — run the skill on not more than 5 to 10 smart contracts. Smaller and tighten scope means that each subagent will perform with cleaner context thus leading to better results.

> [!WARNING]
> Each subagent spawned by this skill provides a solid base ground checklist for the particular area of attack vectors, but it's imperfect! Every month in the web3 world we witness different and more complex varieties of web3 vulnerabilities which means that it's impossible to collect all attack vectors at one place. Updating the subagent's checklists with more and more attack vectors is a never ending process. Treat this skill as a helper and a tool, rather than fully delegating your work on it.