# 0xSplits Contracts Monorepo

## WHAT

Onchain financial operations platform.
Monorepo with two Foundry-based Solidity packages, managed with Turborepo + pnpm:

- `packages/splits-v2` -- Core splitting contracts (Solidity 0.8.23)
- `packages/smart-vaults` -- ERC-4337 smart account abstraction (Solidity 0.8.23)

## WHY (Architecture)

### splits-v2

- **SplitsWarehouse** (`src/SplitsWarehouse.sol`): Central ERC6909 token warehouse. All deposits/withdrawals flow through here. Token IDs = `uint256(uint160(tokenAddress))`.
- **PullSplit** (`src/splitters/pull/PullSplit.sol`): Distributes by depositing to warehouse; recipients claim later. Gas-efficient for many recipients.
- **PushSplit** (`src/splitters/push/PushSplit.sol`): Distributes by sending tokens directly to recipients. Simpler for fewer recipients.
- **SplitWalletV2** (`src/splitters/SplitWalletV2.sol`): Abstract base for split wallets -- manages config, balances, owner.
- **PullSplitFactory / PushSplitFactory** (`src/splitters/pull/` and `push/`): Deploy split instances.
- **SplitFactoryV2** (`src/splitters/SplitFactoryV2.sol`): Abstract factory base using CREATE2 clones.

### smart-vaults

- **SmartVault** (`src/vault/SmartVault.sol`): ERC-4337 v0.7 multi-sig smart account with m-of-n signing.
- **SmartVaultFactory** (`src/vault/SmartVaultFactory.sol`): Deploys vault proxies deterministically.
- **Signers** (`src/signers/`): `MultiSigner`, `AccountSigner` (EOA), `PasskeySigner` (WebAuthn) -- flexible signer architecture.

### splits-v2 Contract Flow

```
                    +-------------------+
                    | SplitsWarehouse   |  (ERC6909 token accounting)
                    +--------+----------+
                             |
                    +--------+----------+
                    |                   |
              +-----v----+      +------v---+
              | PullSplit |      | PushSplit|
              | (claim)   |      | (direct) |
              +-----------+      +----------+
```

## HOW (Development)

### Build

```
pnpm build                                        # all packages (via turbo)
pnpm build:optimized                              # all packages, via-ir optimized
cd packages/splits-v2 && forge build              # single package
```

### Test

```
pnpm test                                         # all packages (via turbo)
cd packages/splits-v2 && forge test -vvv          # single package
forge test --match-path test/SomeTest.t.sol       # single file
forge test --match-test testFunctionName          # single test
forge test --match-path test/X.t.sol --match-test testFoo -vvvv  # specific + verbose
```

### Lint and Format

```
pnpm lint                                         # all (forge fmt --check + solhint)
forge fmt                                         # auto-format Solidity (in package dir)
pnpm format                                       # format non-Solidity files (json, md, yml)
```

### Deploy

Each package has deploy scripts in `script/`. See package READMEs for env setup. Example:
```
cd packages/splits-v2
source .env && FOUNDRY_PROFILE=optimized forge script script/SplitsWarehouse.s.sol --broadcast --verify -vvvvv --rpc-url $RPC_URL
```

## Key Gotchas

- Token IDs in SplitsWarehouse = `uint256(uint160(tokenAddress))`
- Split recipients MUST be sorted by address (ascending) -- validation reverts otherwise
- PullSplit deposits to warehouse first; PushSplit sends directly to recipients
- SmartVault uses ERC-4337 v0.7 EntryPoint (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`)
- Native ETH is wrapped as WETH internally by the warehouse
- Split distributions include an optional distributor incentive (reward for calling distribute)
- Optimizer runs: 5,000,000 (optimized for runtime gas, not deploy cost)

## Deeper References

- splits-v2 contract details: `packages/splits-v2/docs/contracts.md`
- splits-v2 integration patterns: `packages/splits-v2/docs/integration-patterns.md`
- smart-vaults internals: `packages/smart-vaults/docs/contracts.md`
- Architecture diagrams: `packages/*/docs/*.png`
- Deployment config: `packages/*/config/`
- Security audits: `audits/`
