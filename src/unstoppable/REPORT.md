# Damn Vulnerable DeFi V4 - Unstoppable

## Blog Post

<https://hackmd.io/@0xnick/H1NphWBIyx>

## Introduction

There's a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.

To catch any bugs before going 100% permissionless, the developers decided to run a live beta in testnet. There's a monitoring contract to check liveness of the flashloan feature.

Starting with 10 DVT tokens in balance, show that it's possible to halt the vault. It must stop offering flash loans.

## Scope

[Repository](https://github.com/NikolayPIvanov/damn-vulnerable-defi-v4)

- src/unstoppable/UnstoppableMonitor.sol
- src/unstoppable/UnstoppableVault.sol

## Notes

- Uses solidity >= 0.8, overflows are thrown as errors.
- UnstoppableVault is ERC4626-compliant tokenized vault
- Offers flashloans for a fee.
- On `UnstoppableVault::flashLoan` we have incorrect handling of DVT.

## Analysis

### [H-1] Incorrect comparison of shares and total assets can halt flashloans

#### Description

On `UnstoppableVault::flashLoan` we have incorrect handling of DVT assets and supply. This can be used by an attacker to break the functions check for balance between the assets and supply issued.

This can be done simply by transferring DVT to the vault. Which will cause the following check to fail:

```solidity
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

This will cause the `UnstoppableMonitor` contract to pause the vault automatically.

#### Impact

If exploited, this vulnerability could allow malicious actor the halt the execution of the contract's flashloans.

#### Proof of Concepts

We can break the contract by transferring anything from 1 wei to the initial balance of the player.

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
}
```

#### Recommended mitigation

Do not use the current balance of the vault contract.

```solidity
function totalAssets() public view override nonReadReentrant returns (uint256) {
    return asset.balanceOf(address(this));
}
```

Instead keep accounting on deposit and withdraw functions in a separate variable. This will allow
to increase the total assets only from intended functions regardless of the underlying true balance.

```diff
+ uint256 public s_totalAssets;
```

```diff
function flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)
        external
        returns (bool)
    {
        if (amount == 0) revert InvalidAmount(0); // fail early
        if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
-       uint256 balanceBefore = totalAssets();
+       uint256 balanceBefore = s_totalAssets;
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

        // transfer tokens out + execute callback on receiver
        ERC20(_token).safeTransfer(address(receiver), amount);

        // callback must return magic value, otherwise assume it failed
        uint256 fee = flashFee(_token, amount);
        if (
            receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data)
                != keccak256("IERC3156FlashBorrower.onFlashLoan")
        ) {
            revert CallbackFailed();
        }

        // pull amount + fee from receiver, then pay the fee to the recipient
        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);

        return true;
    }
```
