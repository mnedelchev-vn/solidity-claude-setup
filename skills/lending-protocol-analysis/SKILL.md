---
name: lending-protocol-analysis
description: This skill serve as a checklist to identify issues or exploits inside Solidity lending or yield-bearing smart contracts. Another reason why the skill could be used is to validate the correct flow execution of lending and borrowing activies. This skill should be used when dealing with DeFi smart contracts that include deposit & withdraw of collateral ( lending ), borrowing loans and repaying them, flashloans, liquidations or yield harvesting.
---

# Rounding issues and exploits analysis

Detecting vulnerabilities that allow attackers to **harm** lending protocols. Such exploits could be stealing protocol's funds, locking funds, trying to exploit interest or withdrawal fees.

## When to Use

- ???

## When NOT to Use

- Contracts with no lending logic
- Contracts with no yield bearing logic

## Examples of issues and exploits with lending protocols

### Case 1: 


### Advanced cases:

**Liquidations**: See [liquidations.md](resources/liquidations.md) for complete guide



## Additional Analysis

Beyond the patterns above, apply your full security knowledge to identify any related issues not covered here.