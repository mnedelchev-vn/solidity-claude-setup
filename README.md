# Solidity DeFi Claude Skills

## Purpose

The following repository aims to support web3 builders or security researches when dealing with Solidity protocols. Skills are intended not to limit the agent's performance, but rather to sharpen their focus on specific parts of the web3 protocols. Each skill includes precise explanations of when and in what situations it should be invoked. The nature of skills is such that the agent will only invoke them when they are needed by the current user prompt which makes them unique optimized way when dealing with procedural tasks e.g. building or breaking the same of type of DeFi protocols such as lending protocols.

Each skill provides a solid base ground checklist for the particular area of attack vectors, but it's imperfect! Every month we witness different and more complex varities of web3 vulnerabilities and it's impossible to collect everything at one place. Treat the skills as a helper and a tool, rather than fully delegating your work on them.

## Available Skills:

| Skill title | Description |
|----------------|-------------|
| [rounding-issues-and-exploits](skills/rounding-issues-and-exploits/) | Smart contract security toolkit which lists the consequences of Solidity not supporting Floating Point Arithmetic |
| [lending-protocol-analysis](skills/lending-protocol-analysis/) | Lending protocols analysis placing heavy focus on fair liquidations |
| [price-oracles-checklist](skills/price-oracles-checklist) | Price oracles checklist including different attack vectors such as oracle manipulation, weak oracle validation, etc. |
| [erc20-differences-checklist](skills/erc20-differences-checklist) | This skill is a checklist for the differences between ERC20 tokens .e.g missing `decimals()` method, no response on `transfer()` or `transferFrom()` _( USDT )_, etc. |
| [erc721-specifics](skills/erc721-specifics) | Including list of ERC721's' `balanceOf` specifics, posibilities of reentrancy, etc. |
| [signatures-checklist](skills/signatures-checklist) | Covering risks when integrating signatures such as weak  |

## Installation

Copy the specific skill you want your Claude Code agent to use at your general `.claude/skills/` folder _( by doing this the skill will be taken into account by every user prompt in your Claude Code agent, however because of the uniqueness of skills the agent will only skim through the particular skill description and then decide if the skill should be used or not )_:
```
cp -R skills/rounding-issues-and-exploits ~/.claude/skills
```
Or if you want the skill to be taken into account only for specific project or folder then create `.claude/skills/` folder at the root of your project and place the skill there. Now the skill will be active only for user prompts in that specific folder.

## License

This repository is released under the [MIT License](LICENSE).