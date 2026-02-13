# Splits V2 -- Contract Reference

## Overview

Splits V2 is the core splitting protocol from 0xSplits. It provides onchain payment splitting through an architecture that combines an ERC6909-compliant token warehouse with lightweight split wallet clones. The system supports both push and pull distribution models.

For a visual overview of the architecture, see [architecture.png](architecture.png) in this directory.

## Data Flow

1. **Deposit**: Funds arrive at a split wallet (direct transfer or warehouse deposit).
2. **Warehouse**: For pull splits, the wallet deposits tokens into the SplitsWarehouse, which tracks balances as ERC6909 token positions. Token IDs are `uint256(uint160(tokenAddress))`.
3. **Distribute**: Anyone can call `distribute()` on a split wallet, which calculates each recipient's share based on their allocation and sends funds accordingly.
4. **Claim (Pull only)**: Recipients withdraw their warehouse balances at their convenience.

## Pull vs Push Distribution

### Pull Distribution (PullSplit)

Funds are deposited into the SplitsWarehouse and credited to each recipient as ERC6909 balances. Recipients call `withdraw()` on the warehouse to claim their tokens.

**Tradeoffs:**
- Gas-efficient for many recipients (distribution is a batch of internal balance transfers).
- Recipients must actively claim (two-step process).
- No risk of distribution failure from reverting recipient contracts.
- Recipient balances accumulate across multiple distributions before withdrawal.

### Push Distribution (PushSplit)

Funds are sent directly to each recipient via token transfers. For native ETH, if a direct transfer fails (e.g., recipient is a contract that reverts), the amount is deposited to the warehouse as a fallback.

**Tradeoffs:**
- Simpler for few recipients (one-step process).
- Higher gas cost per recipient (external transfers).
- Can fail or behave unexpectedly if a recipient contract reverts on ERC20 transfers.
- Immediate delivery -- recipients do not need to claim.

---

## Core Contracts

### SplitsWarehouse

**Path:** `src/SplitsWarehouse.sol`

Central ERC6909-compliant token warehouse that holds deposited tokens on behalf of split wallets and recipients. Token IDs are derived from token addresses via `uint256(uint160(address))`.

**Inherits:** `ERC6909X`

**Key State:**
- `NATIVE_TOKEN` (constant): `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (per ERC-7528)
- `PERCENTAGE_SCALE` (constant): `1e6`
- `withdrawConfig` (mapping): Per-owner `WithdrawConfig` containing `incentive` (uint16) and `paused` (bool)

**Key Functions:**

| Function | Description |
|---|---|
| `deposit(address _receiver, address _token, uint256 _amount)` | Deposits tokens (or native ETH via msg.value) and mints ERC6909 balance to `_receiver`. |
| `batchDeposit(address[] _receivers, address _token, uint256[] _amounts)` | Deposits tokens to multiple receivers in a single call. |
| `withdraw(address _owner, address _token)` | Withdraws all but 1 of `_owner`'s balance. Bypasses incentives if caller is owner. Reverts if paused and caller is not owner. |
| `withdraw(address _owner, address[] _tokens, uint256[] _amounts, address _withdrawer)` | Withdraws specified amounts with withdrawal incentive paid to `_withdrawer`. Reverts if paused. |
| `batchTransfer(address[] _receivers, address _token, uint256[] _amounts)` | Transfers ERC6909 balances from msg.sender to multiple receivers. Used internally by PullSplit during distribution. |
| `setWithdrawConfig(WithdrawConfig _config)` | Sets the caller's withdrawal incentive and paused state. |

---

### SplitWalletV2

**Path:** `src/splitters/SplitWalletV2.sol`

Abstract base contract for split wallets. Stores the split configuration hash, provides `updateSplit()`, `getSplitBalance()`, and `initialize()`. Inherits `Wallet` (which provides `execCalls()`, pausing, and ownership) and `ERC1271` (for signature validation).

**Inherits:** `Wallet`, `ERC1271`

**Key State:**
- `SPLITS_WAREHOUSE` (immutable): Reference to the SplitsWarehouse.
- `FACTORY` (immutable): Address of the factory that deployed this wallet.
- `splitHash`: Keccak256 hash of the current `SplitV2Lib.Split` struct.

**Key Functions:**

| Function | Description |
|---|---|
| `initialize(SplitV2Lib.Split _split, address _owner)` | Called by factory after cloning. Validates split, stores hash, sets owner. |
| `distribute(...)` | Abstract -- implemented by PullSplit and PushSplit. |
| `getSplitBalance(address _token)` | Returns both the wallet's direct token balance and its warehouse balance. |
| `updateSplit(SplitV2Lib.Split _split)` | Owner-only. Validates and stores a new split configuration hash. |
| `execCalls(Call[] _calls)` | (Inherited from Wallet) Owner-only. Executes arbitrary calls from the wallet. |
| `setPaused(bool _paused)` | (Inherited from Pausable) Owner-only. Pauses/unpauses distribution. |
| `transferOwnership(address _owner)` | (Inherited from Ownable) Owner-only. Transfers wallet ownership. |

---

### SplitFactoryV2

**Path:** `src/splitters/SplitFactoryV2.sol`

Abstract factory that deploys split wallet clones using CREATE2. Provides deterministic and nonce-based creation, plus address prediction.

**Key Functions:**

| Function | Description |
|---|---|
| `createSplitDeterministic(Split, address _owner, address _creator, bytes32 _salt)` | Creates a split via CREATE2 using a salt derived from params + owner + salt. Returns existing address if already deployed. |
| `createSplit(Split, address _owner, address _creator)` | Creates a split using an auto-incrementing nonce. Avoids salt management and front-running. |
| `predictDeterministicAddress(Split, address _owner, bytes32 _salt)` | Predicts the address for a deterministic deployment. |
| `isDeployed(Split, address _owner, bytes32 _salt)` | Returns predicted address and whether it has code. |

**Relationships:** Extended by PullSplitFactory and PushSplitFactory.

---

### PullSplit

**Path:** `src/splitters/pull/PullSplit.sol`

Split wallet that distributes funds through the warehouse (pull model). During distribution, tokens held by the wallet are first deposited into the warehouse, then warehouse balances are batch-transferred to recipients.

**Key Functions:**

| Function | Description |
|---|---|
| `distribute(Split, address _token, address _distributor)` | Distributes the full balance (wallet + warehouse, minus 1 each for gas savings). |
| `distribute(Split, address _token, uint256 _amount, bool _performWarehouseTransfer, address _distributor)` | Distributes a specific amount. |
| `depositToWarehouse(address _token, uint256 _amount)` | Deposits tokens from the wallet into the warehouse. |

---

### PullSplitFactory

**Path:** `src/splitters/pull/PullSplitFactory.sol`

Concrete factory for PullSplit wallets. Deploys a PullSplit implementation in its constructor and uses it as the clone source.

---

### PushSplit

**Path:** `src/splitters/push/PushSplit.sol`

Split wallet that distributes funds directly to recipients (push model). Withdraws any warehouse balance first, then sends tokens via direct transfers. For native ETH, falls back to warehouse deposit if direct transfer fails.

**Key Functions:**

| Function | Description |
|---|---|
| `distribute(Split, address _token, address _distributor)` | Distributes the full balance. Withdraws from warehouse, then pushes directly. |
| `distribute(Split, address _token, uint256 _amount, bool _performWarehouseTransfer, address _distributor)` | Distributes a specific amount. |
| `withdrawFromWarehouse(address _token)` | Withdraws the wallet's warehouse balance back to the wallet. |

---

### PushSplitFactory

**Path:** `src/splitters/push/PushSplitFactory.sol`

Concrete factory for PushSplit wallets. Deploys a PushSplit implementation in its constructor and uses it as the clone source.

---

## Libraries

### Cast (`src/libraries/Cast.sol`)
Type-casting utilities for converting between `address`, `uint256`, and `uint160`. Reverts with `Overflow()` if a uint256 exceeds 160 bits.

### Clone (`src/libraries/Clone.sol`)
Modified minimal proxy library (based on Solady's LibClone). Deploys clones via CREATE2 with a built-in `receive()` that emits `ReceiveETH(uint256)` to avoid DELEGATECALL overhead on plain ETH transfers.

### Math (`src/libraries/Math.sol`)
Minimal math: `sum(uint256[])` for calldata and memory arrays, and `min(uint256, uint256)`.

### SplitV2Lib (`src/libraries/SplitV2.sol`)
Core split logic. Defines the `Split` struct:

```solidity
struct Split {
    address[] recipients;     // MUST be sorted ascending by address
    uint256[] allocations;
    uint256 totalAllocation;
    uint16 distributionIncentive;  // max ~6.5%, scaled by PERCENTAGE_SCALE (1e6)
}
```

Key functions: `getHash()`, `validate()`, `getDistributions()`, `calculateAllocatedAmount()`, `calculateDistributorReward()`.

---

## Interfaces

- **IERC6909** (`src/interfaces/IERC6909.sol`): Core ERC-6909 multi-token interface.
- **IERC6909X** (`src/interfaces/IERC6909X.sol`): Extension for signature-based approvals (`temporaryApproveAndCall`, `approveBySig`).
- **ISplitsWarehouse** (`src/interfaces/ISplitsWarehouse.sol`): Warehouse interface (`deposit`, `batchDeposit`, `batchTransfer`, `withdraw`).
- **IWETH9** (`src/interfaces/IWETH9.sol`): Standard WETH9 interface.

---

## Tokens

- **ERC6909** (`src/tokens/ERC6909.sol`): Gas-efficient ERC-6909 implementation (based on Solmate). Multi-token `balanceOf`, `transfer`, `approve`, `setOperator`.
- **ERC6909X** (`src/tokens/ERC6909X.sol`): Extends ERC6909 with EIP-712 signature-based approvals and `temporaryApproveAndCall()`. Uses `UnorderedNonces` for replay protection.

---

## Utils

- **ERC1271** (`src/utils/ERC1271.sol`): Signature validation with EIP-712 replay protection. Wraps hashes with `SplitWalletMessage(bytes32 hash)`.
- **Nonces** (`src/utils/Nonces.sol`): Hash-based incrementing nonce tracker for nonce-based split creation.
- **Ownable** (`src/utils/Ownable.sol`): Minimal ownable for clone wallets. `onlyOwner` allows both `owner` and `address(this)` (for `execCalls()`).
- **Pausable** (`src/utils/Pausable.sol`): Extends Ownable with `paused` flag. Used to gate `distribute()` and `depositToWarehouse()`.
- **UnorderedNonces** (`src/utils/UnorderedNonces.sol`): Bitmap-based unordered nonce tracker (inspired by Uniswap Permit2). Used by ERC6909X.
- **Wallet** (`src/utils/Wallet.sol`): Minimal smart wallet. Extends Pausable, ERC721Holder, ERC1155Holder. Provides `execCalls(Call[])` for batched arbitrary calls.
