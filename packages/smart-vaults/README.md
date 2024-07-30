# Smart Vaults

Smart accounts signature scheme for Single/Bundled User Ops and ERC1271 with light state sync.

```mermaid
classDiagram
    SignatureType <|-- Signature
    UserOpSignatureType <|-- UserOpSignature
    Signature <|-- UserOpSignature
    Signature <|-- LightSyncSignature
    UserOpSignature <|-- MultiOpSignature
    LightSyncSignature *-- SignerSetUpdate
    MultiOpSignature *-- SignatureWrapper
    UserOpSignature *-- SignatureWrapper
    SignerSetUpdate *-- SignatureWrapper

    class SignatureType {
        <<enumeration>>
        UserOp
        LightSync
    }

    class Signature {
        SignatureType sigType
        bytes signature
    }

    class UserOpSignatureType {
        <<enumeration>>
        Single
        Multi
    }

    class UserOpSignature {
        UserOpSignatureType sigType
        bytes signature
    }

    class MultiOpSignature {
        bytes32 lightMerkleTreeRoot
        bytes32[] lightMerkleProof
        bytes32 merkleTreeRoot
        bytes32[] merkleProof
        bytes normalSignature
    }

    class LightSyncSignature {
        SignerSetUpdate[] updates
        bytes userOpSignature
    }

    class SignerSetUpdate {
        bytes data
        bytes normalSignature
    }

    class SignatureWrapper {
        uint8 signerIndex
        bytes signatureData
    }
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
