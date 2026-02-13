# Splits V2

Core splitting contracts for the 0xSplits protocol. Enables onchain payment splitting among multiple recipients with configurable allocations and distribution incentives.

## Source Layout

```
src/
  SplitsWarehouse.sol         -- ERC6909 token warehouse (deposits, withdrawals, balances)
  splitters/
    SplitWalletV2.sol         -- Abstract base split wallet (config, ownership, pausing)
    SplitFactoryV2.sol        -- Abstract factory (CREATE2 clones, address prediction)
    pull/
      PullSplit.sol           -- Pull distribution (deposit to warehouse, recipients claim)
      PullSplitFactory.sol    -- Factory for PullSplit instances
    push/
      PushSplit.sol           -- Push distribution (send directly to recipients)
      PushSplitFactory.sol    -- Factory for PushSplit instances
  libraries/                  -- Cast, Clone, Math, SplitV2Lib
  interfaces/                 -- IERC6909, ISplitsWarehouse, IWETH9
  tokens/                     -- ERC6909, ERC6909X (with signature-based approvals)
  utils/                      -- ERC1271, Ownable, Pausable, Wallet, Nonces
```

## Commands (run from this directory)

```
forge build                                       # build
forge test -vvv                                   # test all
forge test --match-path test/SomeTest.t.sol       # test single file
forge test --match-test testFoo -vvvv             # test single function
forge fmt                                         # format
forge coverage                                    # coverage
```

## Key Concepts

- Token IDs in warehouse = `uint256(uint160(tokenAddress))`
- Split recipients must be sorted ascending by address
- distributionIncentive: reward for calling distribute, scaled by 1e6

## Deep Dive

- Contract details: `docs/contracts.md`
- Integration patterns: `docs/integration-patterns.md`
- Architecture diagram: `docs/architecture.png`
