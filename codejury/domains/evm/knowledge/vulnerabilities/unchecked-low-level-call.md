---
id: unchecked-low-level-call
title: Unchecked Low-Level Call
impact: HIGH
tags: [swc-104, low-level-call, return-value, fund-loss]
triggers: [".call(", ".call{value", ".delegatecall(", ".send(", "transfer(", "bool success", "bool ok", "(bool", "safeTransfer", "returndata"]
---

## Unchecked Low-Level Call

A low-level `.call`, `.delegatecall`, or `.send` returns success as a boolean rather than
reverting on failure. Ignoring that return value lets a failed transfer or call pass
silently, so the contract proceeds as if value moved when it did not, the accounting and
the reality diverge, and funds are credited or marked sent without leaving. Likewise a
raw ERC-20 `transfer` on a token that returns false on failure, or returns nothing, must
be checked or wrapped with SafeERC20. Check every low-level return, or use a wrapper that
reverts.

### Vulnerable
```solidity
function payout(address to, uint256 amount) external {
    to.call{value: amount}("");          // return value ignored, a failed send looks successful
    paid[to] += amount;                   // credited even though nothing left the contract
}
```

### Secure
```solidity
function payout(address to, uint256 amount) external {
    (bool ok, ) = to.call{value: amount}("");
    require(ok, "transfer failed");       // failure reverts, accounting stays true
    paid[to] += amount;
}
```
