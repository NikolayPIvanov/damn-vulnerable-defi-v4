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

- Must send request through truster forwarder.
- `_msgSender` in `NaiveReceiverPool` is working wit the last bytes and might be a possible exploit.
  - Gets the last 20 bytes from the data (an attacker can encode whatever they want in here)
  - We need to move the 10 ETH from receiver to the pool (we can take 10 flash loans until there is no more ether)
  - Fee Receiver == Deployer that means that all funds are held by the deployer
  - with this we can get all the WETH into the pool under the deployer address in `deposits` then impersonated the deployer by using the last 20 bytes in the call data.

## Analysis
