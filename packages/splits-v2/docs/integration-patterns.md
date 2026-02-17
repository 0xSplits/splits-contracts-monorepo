# Splits V2 -- Integration Patterns

Common scenarios for integrating with the Splits V2 protocol.

## 1. Creating a Split

Use the factory for your chosen distribution model.

```solidity
import { PullSplitFactory } from "splits-v2/src/splitters/pull/PullSplitFactory.sol";
import { SplitV2Lib } from "splits-v2/src/libraries/SplitV2.sol";

SplitV2Lib.Split memory split = SplitV2Lib.Split({
    recipients: [address(0x111...), address(0x222...), address(0x333...)],
    allocations: [300_000, 500_000, 200_000],  // 30%, 50%, 20%
    totalAllocation: 1_000_000,
    distributionIncentive: 10_000  // 1% reward for distributor (scaled by 1e6)
});

// Deterministic deployment (predictable address)
address splitWallet = factory.createSplitDeterministic(split, owner, msg.sender, salt);

// Or nonce-based (no salt needed, no front-running risk)
address splitWallet = factory.createSplit(split, owner, msg.sender);
```

Use `PushSplitFactory` instead for push-based distribution.

## 2. Distributing Funds

Anyone can call `distribute()` on a split wallet. The distributor earns the `distributionIncentive`.

```solidity
import { PullSplit } from "splits-v2/src/splitters/pull/PullSplit.sol";

// Distribute all available tokens (wallet balance + warehouse balance)
PullSplit(splitWallet).distribute(split, tokenAddress, msg.sender);

// Distribute a specific amount
PullSplit(splitWallet).distribute(split, tokenAddress, amount, true, msg.sender);
```

The `split` struct must match the stored `splitHash` or the call reverts.

## 3. Updating Split Recipients

Only the split owner can update the configuration.

```solidity
SplitV2Lib.Split memory newSplit = SplitV2Lib.Split({
    recipients: [address(0x111...), address(0x444...)],
    allocations: [600_000, 400_000],
    totalAllocation: 1_000_000,
    distributionIncentive: 10_000
});

SplitWalletV2(splitWallet).updateSplit(newSplit);
```

## 4. Depositing to the Warehouse

Any contract can deposit tokens into the warehouse on behalf of a recipient.

```solidity
import { ISplitsWarehouse } from "splits-v2/src/interfaces/ISplitsWarehouse.sol";

// ERC20 deposit (must approve warehouse first)
IERC20(token).approve(address(warehouse), amount);
warehouse.deposit(recipient, token, amount);

// Native ETH deposit
warehouse.deposit{value: amount}(recipient, address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE), amount);

// Batch deposit to multiple recipients
warehouse.batchDeposit(recipients, token, amounts);
```

## 5. Withdrawing from the Warehouse

Recipients claim their accumulated balances.

```solidity
// Simple withdrawal (all but 1 wei of a single token)
warehouse.withdraw(ownerAddress, tokenAddress);

// Batch withdrawal with incentive
warehouse.withdraw(ownerAddress, tokens, amounts, withdrawerAddress);
```

The owner can configure withdrawal incentives and pause withdrawals:

```solidity
warehouse.setWithdrawConfig(ISplitsWarehouse.WithdrawConfig({
    incentive: 5000,  // 0.5% incentive for third-party withdrawers
    paused: false
}));
```

## 6. Pull vs Push: Decision Guide

| Factor                      | Pull (PullSplit)                                  | Push (PushSplit)                                            |
| --------------------------- | ------------------------------------------------- | ----------------------------------------------------------- |
| Gas cost per distribution   | Lower (internal balance transfers)                | Higher (external token transfers)                           |
| Recipient count             | Better for many recipients                        | Better for few recipients                                   |
| Recipient must claim?       | Yes (call warehouse.withdraw)                     | No (tokens arrive directly)                                 |
| Risk of failed distribution | None (warehouse accounting)                       | Can fail if recipient reverts (ETH falls back to warehouse) |
| Composability               | Recipients can use warehouse balances via ERC6909 | Standard token transfers                                    |
| Best for                    | Protocols, DAOs, many-party splits                | Simple 2-3 party splits, EOA recipients                     |

**Default recommendation:** Use PullSplit unless you have a specific reason to prefer push (e.g., simple 2-party split
with EOA recipients).

## 7. Security Considerations

**Audits:** See the `audits/` directory at the repo root for completed audit reports.

**Key invariants:**

- `distribute()` leaves 1 wei in both the wallet and warehouse to avoid gas costs of zeroing storage slots.
- The `onlyOwner` modifier allows both `owner` and `address(this)`, enabling batched calls via `execCalls()`.
- `Pausable.pausable` modifier allows the owner, `tx.origin == owner`, or `address(this)` to bypass the pause, so
  pausing only blocks third parties.
- Withdrawal pausing (`withdrawConfig.paused`) only blocks third-party withdrawals. The owner can always withdraw their
  own funds.

**Integration checklist:**

- Validate your split struct off-chain before submitting (check allocations sum to totalAllocation).
- If integrating as a recipient, consider using the warehouse's ERC6909 balances directly instead of withdrawing.
- Set `distributionIncentive` > 0 if you want third parties to call distribute on your behalf.
