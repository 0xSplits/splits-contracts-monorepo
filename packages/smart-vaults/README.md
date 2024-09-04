# Smart Vaults

Splits 4337 smart accounts are engineered to provide users with a seamless and secure way to manage a tiered system of
multi-chain multi-sigs. This means minimizing user friction to synchronize state (e.g. implementation, signer set)
across networks without degrading the underlying security model.

![architecture](./docs/smart%20account%20architecture.png)

Currently, these smart accounts are compatible with entry point
[v0.7](https://github.com/eth-infinitism/account-abstraction/tree/releases/v0.7).

## Feature set

- **m-of-n signers**: Supports both [**Passkeys**](https://splits.org/blog/passkeys-developers/) and **EOAs**.
- **ERC1271 Support**: Can verify [**ERC1271**](https://eips.ethereum.org/EIPS/eip-1271) signatures.
- **Token Support**: Accepts **ERC721** and **ERC1155**(single and batch) tokens.
- **Fallback Manager**: Allows users to extend their smart accounts to handle future callback-based interactions, such
  as those involving **ERC721** tokens, ensuring future-proofing.
- **Module Manager**: Provides users the ability to add trusted modules that can interact on behalf of the smart
  account.
- **Contract Deployment**: Enables the deployment of new contracts using `create` from within the smart account during a
  UserOp.
- **[Merkelized User Operations](#merkelized-user-operations)**: Supports signing once for multiple user operations
  across different networks and accounts using Merkle trees.
- **[Light User Operation](#light-user-operation)**: When multiple signatures are required, allows the last signer to
  set gas according to current market conditions.

### Merkelized User Operations

Merkelized User Operations utilize **Merkle trees** to generate a root of all intended user operations. The user signs
the Merkle root once, and when submitting a user operation, the signature includes the Merkle proof for verification.
There is no strict limit on the number of operations or which parameters should remain constant, allowing operations
across multiple networks and smart accounts with a single signature.

### Light User Operation

When the **threshold** (the number of unique and valid signatures required for a valid user operation) is greater than
**1**, the first **threshold - 1** signers sign over a reduced set of properties from the user operation. This gives the
final signer flexibility to price gas for the user operation inline with current market conditions. In the case of
Merkelized User Operations, the initial signatures are verified against a **light** Merkle root, constructed using these
reduced light user operations.

Properties included in light UserOp:

- **sender**
- **nonce**
- **calldata**

Properties excluded:

- **initCode** - This has been excluded because of `sender` since `sender` is calculated deterministically from
  `initCode` making it redundant.
- **accountGasLimits**
- **preVerificationGas**
- **gasFees**
- **paymasterAndData**
- **signature**

## Build

`pnpm build`

## Test

`pnpm test`

### Coverage

`pnpm test:coverage`

### Coverage Report

`pnpm test:coverage:report`

## Lint

`pnpm lint`

### Format

`pnpm format`

## Developers/Integrators

### Foundry

`forge install 0xSplits/splits-contracts-monorepo`
