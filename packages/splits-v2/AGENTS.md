# Splits V2

Core splitting contracts for the 0xSplits protocol. Enables onchain payment splitting among multiple recipients with
configurable allocations and distribution incentives.

## Source Layout

```bash
src/
  SplitsWarehouse.sol         # ERC6909 token warehouse (deposits, withdrawals, balances)
  splitters/
    SplitWalletV2.sol         # Abstract base split wallet (config, ownership, pausing)
    SplitFactoryV2.sol        # Abstract factory (CREATE2 clones, address prediction)
    pull/
      PullSplit.sol           # Pull distribution (deposit to warehouse, recipients claim)
      PullSplitFactory.sol    # Factory for PullSplit instances
    push/
      PushSplit.sol           # Push distribution (send directly to recipients)
      PushSplitFactory.sol    # Factory for PushSplit instances
  libraries/                  # Cast, Clone, Math, SplitV2Lib
  interfaces/                 # IERC6909, ISplitsWarehouse, IWETH9
  tokens/                     # ERC6909, ERC6909X (with signature-based approvals)
  utils/                      # ERC1271, Ownable, Pausable, Wallet, Nonces
```

## Commands (run from this directory)

```bash
pnpm build                                        # build
pnpm test                                         # test all
pnpm test --match-path test/SomeTest.t.sol        # test single file
pnpm test --match-test testFoo -vvvv              # test single function
pnpm lint                                         # lint
pnpm format                                       # format
pnpm coverage                                     # coverage
```

## Key Concepts

- Token IDs in warehouse = `uint256(uint160(tokenAddress))`
- distributionIncentive: reward for calling distribute, scaled by 1e6

## Deep Dive

- Contract details: `docs/contracts.md`
- Integration patterns: `docs/integration-patterns.md`
- Architecture diagram: `docs/architecture.png`
