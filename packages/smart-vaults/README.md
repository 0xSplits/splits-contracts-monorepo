# Smart Vaults

Smart accounts signature scheme for Single/Merkelized User Ops and ERC1271 with light state sync.

```mermaid
---
title: Signature Packing
---
flowchart
    direction TB
    Signature -.-> UserOp
    Signature -.-> LightSync

    LightSync --> add-signers --> UserOp

    UserOp -.-> SingleOp
    UserOp -.-> MerkelizedOp
```

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
