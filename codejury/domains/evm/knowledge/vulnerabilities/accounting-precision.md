---
id: accounting-precision
title: Accounting and Precision Error
lens: accounting-precision
impact: HIGH
tags: [accounting, rounding, precision, erc4626, fund-loss]
aliases: [accounting, precision]
triggers: ["* totalSupply", "/ totalSupply", "shares", "convertToShares", "convertToAssets", "totalAssets", "/ ", "mulDiv", "first deposit", "previewDeposit", "rounding"]
---

## Accounting and Precision Error

Share, fee, or balance math rounds in the attacker's favor, divides before multiplying
and loses precision, or lets a first depositor manipulate the share price. The ERC-4626
first-depositor attack deposits 1 wei to mint 1 share, donates a large amount directly to
the vault to inflate the share price, then later depositors round down to 0 shares and
their deposit is captured. Round shares against the user and assets against the vault,
multiply before dividing, and seed or cap the first deposit.

### Vulnerable
```solidity
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = totalSupply == 0 ? assets : (assets * totalSupply) / totalAssets();   // first depositor inflates
    _mint(msg.sender, shares);                                                     // later deposits round to 0
}
```

### Secure
```solidity
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = _convertToShares(assets, Math.Rounding.Down);   // round against the depositor
    require(shares > 0, "zero shares");                       // reject dust that rounds to nothing
    _mint(msg.sender, shares);
}
// plus dead shares minted at construction, so totalSupply is never zero on a real deposit
```
