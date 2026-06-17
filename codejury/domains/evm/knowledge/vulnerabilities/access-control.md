---
id: access-control
title: Missing or Broken Access Control
impact: CRITICAL
tags: [swc-105, swc-115, access-control, fund-loss]
aliases: [missing-access-control, broken-access-control]
triggers: ["onlyOwner", "function mint", "function burn", "function withdraw", "selfdestruct", "tx.origin", "require(msg.sender", "_mint", "setOwner", "transferOwnership", "external", "public"]
---

## Missing or Broken Access Control

A privileged function, one that moves funds, mints or burns, sets a critical parameter,
upgrades, or destroys the contract, is callable by an account that should not reach it.
The cause is a missing modifier, a modifier on the wrong function, an authorization on
`tx.origin` instead of `msg.sender`, or a check that proves the caller is some address
but not the right one. Gate every state-changing privileged function to the exact role,
and use `msg.sender`.

### Vulnerable
```solidity
function mint(address to, uint256 amount) external {   // no access control
    _mint(to, amount);                                  // anyone mints unlimited supply
}

function withdrawAll() external {
    require(tx.origin == owner);                         // tx.origin is phishable
    payable(msg.sender).transfer(address(this).balance);
}
```

### Secure
```solidity
function mint(address to, uint256 amount) external onlyMinter {
    _mint(to, amount);
}

function withdrawAll() external onlyOwner {             // msg.sender, scoped role
    payable(owner).transfer(address(this).balance);
}
```
