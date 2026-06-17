---
id: reentrancy
title: Reentrancy
impact: CRITICAL
tags: [swc-107, reentrancy, fund-loss]
aliases: [read-only-reentrancy]
triggers: [".call{value", ".call(", "transfer(", "send(", "external call", "balances[", "withdraw", "nonReentrant", "safeTransfer", "onERC721Received", "before state"]
---

## Reentrancy

An external call hands control to the callee before the contract finishes updating its
own state, so the callee can call back in and act on the stale pre-update state. The
classic form drains a balance by re-entering a withdraw before the balance is zeroed.
Cross-function reentrancy re-enters a different function that shares the same state, and
read-only reentrancy reads a view mid-update from another protocol. Write state before
the external call, or guard with `nonReentrant`, and remember a guard does not stop the
cross-contract read-only form.

### Vulnerable
```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");   // call before the state update
    require(ok);
    balances[msg.sender] = 0;                          // too late, attacker reentered
}
```

### Secure
```solidity
function withdraw() external nonReentrant {
    uint256 bal = balances[msg.sender];
    balances[msg.sender] = 0;                          // effects before interaction
    (bool ok, ) = msg.sender.call{value: bal}("");
    require(ok);
}
```
