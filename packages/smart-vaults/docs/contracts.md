# Smart Vaults -- Contract Documentation

## Overview

Smart Vaults are ERC-4337-compatible multi-signature smart accounts built for the Splits ecosystem. They allow teams to collectively control on-chain operations through a threshold-based signing scheme that supports both EOA wallets and WebAuthn passkeys.

The architecture is based on Coinbase's Smart Wallet and Solady's Smart Wallet. Each vault is deployed as an ERC-1967 proxy via a deterministic factory, making addresses predictable before deployment.

See `docs/smart account architecture.png` for a visual diagram of the system.

## ERC-4337 Account Abstraction

Smart Vaults implement the `IAccount` interface from ERC-4337. The EntryPoint contract (v0.7, at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`) calls `validateUserOp` on the vault to verify that a user operation has been properly authorized by the required threshold of signers. The vault pays back any missing prefund to the EntryPoint via the `payPrefund` modifier.

The owner can also call `execute` and `executeBatch` directly, bypassing the EntryPoint.

## Signer Architecture

### Signer (`src/signers/Signer.sol`)

The base signer abstraction. A `Signer` is a two-slot struct (`slot1`, `slot2`) that can represent either:

- **EOA**: `slot2` is zero, `slot1` contains the address (left-padded to bytes32).
- **Passkey**: `slot2` is non-zero. `slot1` and `slot2` encode the x and y coordinates of the secp256r1 public key.

`SignerLib` provides type-checking (`isEOA`, `isPasskey`, `isValid`) and dispatches signature verification to the appropriate signer-specific library.

### AccountSigner (`src/signers/AccountSigner.sol`)

Handles signature verification for EOA and ERC-1271 smart account signers. Uses Solady's `SignatureCheckerLib.isValidSignatureNow`, supporting both ECDSA and ERC-1271 contract signatures. The message hash is wrapped with `toEthSignedMessageHash` before verification.

### PasskeySigner (`src/signers/PasskeySigner.sol`)

Handles WebAuthn/passkey signature verification. Decodes the `Signer` struct into x/y coordinates and verifies using the `WebAuthn` library (forked from Coinbase/Daimo). User verification (`requireUV`) is set to `false`.

### MultiSigner (`src/signers/MultiSigner.sol`)

Manages an m-of-n threshold signer set:

- Supports up to 256 signers (stored in a fixed-size `Signer[256]` array).
- Tracks `threshold` (minimum signatures required) and `signerCount`.
- Adding a signer at an occupied index reverts; removing from an empty index reverts.
- Threshold cannot be zero and cannot exceed `signerCount`.
- Removing a signer when `signerCount == threshold` reverts.

Signature validation supports two modes:
1. **Single-hash**: All signers verify the same hash (used for ERC-1271).
2. **Front/back hash split**: First `threshold - 1` signers verify a "front hash" (light hash), final signer verifies the "back hash" (full userOp hash). This enables gas validation (see below).

A bitmask prevents duplicate signers within a single validation.

## UserOp Validation Flow

When `validateUserOp` is called, the first byte of the signature determines the scheme:

### SingleUserOp (type 0)

For submitting a single user operation.

1. Signature decoded as `SingleUserOpSignature` containing gas limits and `SignatureWrapper[]`.
2. If `threshold > 1`: gas limits are verified against actual userOp values. A "light userOp hash" is computed (covers sender, nonce, callData, gas limits, entryPoint, chainId -- but NOT the gas/fee fields from the actual userOp).
3. First `threshold - 1` signatures verified against the light hash; final signature verified against the full `userOpHash`.
4. If `threshold == 1`: only the full `userOpHash` is verified.

### MerkelizedUserOp (type 1)

For batch-approving a set of user operations via merkle trees.

1. Signature decoded as `MerkelizedUserOpSignature` containing gas limits, light/full merkle tree roots, merkle proofs, and signatures.
2. The full `userOpHash` is verified as a leaf of the full merkle tree. The light hash is verified as a leaf of the light merkle tree (if threshold > 1).
3. First `threshold - 1` signatures verified against `lightMerkleTreeRoot`; final against `merkleTreeRoot`.

This allows signers to pre-approve a batch. Individual operations are submitted separately with proofs.

### ERC-1271 (off-chain signature validation)

For standard `isValidSignature(bytes32, bytes)` calls. The hash is wrapped with the EIP-712 domain separator via `replaySafeHash` to prevent cross-account replay. All signers verify the same replay-safe hash (no front/back split).

## Gas Validation

The "light hash" / "front-back split" scheme solves a multi-sig problem: the last signer to submit controls gas parameters. Without protection, they could set arbitrarily high gas prices.

The solution:
1. First `threshold - 1` signers sign a "light" version including `LightUserOpGasLimits` -- upper bounds for `maxPriorityFeePerGas`, `preVerificationGas`, `callGasLimit`, `verificationGasLimit`, and paymaster gas limits.
2. `_verifyGasLimits` checks actual userOp gas values don't exceed these bounds.
3. The final signer signs the full userOp hash with actual gas values.

When `threshold == 1`, this mechanism is skipped entirely.

## Paymaster Support

Smart Vaults support ERC-4337 paymasters for gas sponsorship. When `paymasterAndData` is present, gas validation also verifies the paymaster address matches and gas limits don't exceed approved values.

## UUPS Upgradeability

Uses Solady's `UUPSUpgradeable`. The `_authorizeUpgrade` function is restricted to the vault owner. Each vault is an ERC-1967 proxy pointing to the shared implementation. Read via `getImplementation()`.

## Modules and Fallback Handlers

### ModuleManager (`src/utils/ModuleManager.sol`)

Allows whitelisted "module" contracts to execute calls from the vault via `executeFromModule`. Module management (enable/disable) requires self-authorization (vault calls itself via a userOp). Modules can be set up or torn down with external calls during enable/disable.

### FallbackManager (`src/utils/FallbackManager.sol`)

Routes unrecognized function calls to registered handler contracts based on the 4-byte selector. Extends the vault's interface without upgrading the implementation. ERC-721 and ERC-1155 token callbacks are handled natively via Solady's `Receiver`. Handler registration requires self-authorization.

---

## Contract Reference

### SmartVault (`src/vault/SmartVault.sol`)

Core ERC-4337 smart account. Inherits from `IAccount`, `Ownable`, `UUPSUpgradeable`, `MultiSignerAuth`, `ERC1271`, `FallbackManager`, `ModuleManager`.

| Function | Description |
|---|---|
| `initialize(address owner_, Signer[] signers_, uint8 threshold_)` | Called once by factory. Sets owner and signer config. |
| `validateUserOp(PackedUserOperation, bytes32, uint256) -> uint256` | ERC-4337 signature validation. Dispatches to SingleUserOp or MerkelizedUserOp. |
| `execute(Call)` | Execute a single call. Restricted to EntryPoint or owner. |
| `executeBatch(Call[])` | Execute multiple calls. Restricted to EntryPoint or owner. |
| `entryPoint() -> address` | Returns EntryPoint v0.7 address. |
| `getImplementation() -> address` | Returns current UUPS implementation. |
| `deployCreate(bytes initCode_) -> address` | Deploy contract via CREATE. Self-call only. |
| `isValidSignature(bytes32, bytes) -> bytes4` | ERC-1271 validation. |

### SmartVaultFactory (`src/vault/SmartVaultFactory.sol`)

Deterministic factory for deploying vault proxies.

| Function | Description |
|---|---|
| `createAccount(address owner_, Signer[], uint8 threshold_, uint256 salt_) -> SmartVault` | Deploy or return existing deterministic proxy. Initializes on first deploy. |
| `getAddress(address owner_, Signer[], uint8 threshold_, uint256 salt_) -> address` | Predict vault address without deploying. |
| `initCodeHash() -> bytes32` | Proxy init code hash for address prediction. |

### MultiSignerAuth (`src/utils/MultiSignerAuth.sol`)

Bridges `MultiSignerLib` to the vault, exposing signer management as external functions.

| Function | Description |
|---|---|
| `getSigner(uint8) -> Signer` | Read signer at index. |
| `getSignerCount() -> uint8` | Number of active signers. |
| `getThreshold() -> uint8` | Current threshold. |
| `addSigner(Signer, uint8)` | Add signer at index. Self-authorized. |
| `removeSigner(uint8)` | Remove signer by index. Self-authorized. |
| `updateThreshold(uint8)` | Change threshold. Self-authorized. |

### Supporting Contracts

- **ERC1271** (`src/utils/ERC1271.sol`): Replay-safe signature validation with EIP-712 domain `splitsSmartVault` v1.
- **Caller** (`src/utils/Caller.sol`): Low-level call execution with `Call` struct (`target`, `value`, `data`).
- **UserOperationLib** (`src/library/UserOperationLib.sol`): Packing/hashing ERC-4337 user operations. `hashLight()` excludes gas fields; `hash()` includes all fields.
- **WebAuthn** (`src/library/WebAuthn.sol`): WebAuthn assertion verification (forked from Coinbase/Daimo). Tries RIP-7212 precompile first, falls back to FreshCryptoLib.
