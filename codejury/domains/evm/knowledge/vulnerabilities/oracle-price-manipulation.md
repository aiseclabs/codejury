---
id: oracle-price-manipulation
title: Oracle and Price Manipulation
impact: CRITICAL
tags: [oracle, price-manipulation, flash-loan, fund-loss]
aliases: [oracle, oracle-manipulation, oracle-validation, price-manipulation]
triggers: ["getReserves", "slot0", "balanceOf(address(this))", "balanceOf(this)", "totalSupply", "price", "getAmountOut", "spot", "twap", "latestRoundData", "/ reserve"]
---

## Oracle and Price Manipulation

A contract reads a price or value from a source an attacker can move within one
transaction, a spot AMM price, the pool reserves, or a raw `balanceOf` used as a price,
then acts on it: mints shares, sets collateral value, or computes a swap. A flash loan
lets the attacker move that source for free, drain the difference, and repay in the same
transaction. Price the asset off a manipulation-resistant source, a TWAP or a vetted
oracle with a staleness and bounds check, never an instantaneous on-chain spot read.

### Vulnerable
```solidity
function collateralValue() public view returns (uint256) {
    (uint112 r0, uint112 r1, ) = pair.getReserves();   // spot reserves, flash-loan movable
    return (r1 * 1e18) / r0;                             // attacker sets this within one tx
}
```

### Secure
```solidity
function collateralValue() public view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
    require(price > 0 && block.timestamp - updatedAt < MAX_AGE, "stale");   // vetted, bounded
    return uint256(price);
}
```
