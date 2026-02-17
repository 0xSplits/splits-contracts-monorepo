# Smart Vaults

ERC-4337 multi-signature smart accounts for the Splits ecosystem. Supports m-of-n threshold signing with both EOA
wallets and WebAuthn passkeys.

## Source Layout

```bash
src/
  vault/
    SmartVault.sol            # Core 4337 smart account (validation, execution, upgrades)
    SmartVaultFactory.sol     # Deterministic factory for vault proxies
  signers/
    MultiSigner.sol           # m-of-n threshold signer management
    Signer.sol                # Base signer abstraction (EOA or passkey)
    AccountSigner.sol         # EOA/ERC-1271 signature verification
    PasskeySigner.sol         # WebAuthn passkey verification
  library/
    UserOperationLib.sol      # UserOp packing/hashing (light and full)
    WebAuthn.sol              # WebAuthn assertion verification
  utils/
    Caller.sol                # Low-level call execution
    ERC1271.sol               # Replay-safe signature validation
    FallbackManager.sol       # Extensible function routing by selector
    ModuleManager.sol         # Whitelisted module execution
    MultiSignerAuth.sol       # Signer management external interface
```

## Commands (run from this directory)

```bash
forge build                                       # build
forge test -vvv                                   # test all
forge test --match-path test/SomeTest.t.sol       # test single file
forge test --match-test testFoo -vvvv             # test single function
forge fmt                                         # format
forge coverage                                    # coverage
```

## Key Concepts

- EntryPoint v0.7: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- Three validation modes: SingleUserOp, MerkelizedUserOp, ERC-1271
- Gas validation: first threshold-1 signers sign light hash with gas bounds, final signer signs full hash
- UUPS upgradeable, owner-authorized

## Deep Dive

- Contract details: `docs/contracts.md`
- Architecture diagram: `docs/smart account architecture.png`
