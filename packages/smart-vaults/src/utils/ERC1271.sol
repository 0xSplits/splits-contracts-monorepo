// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ERC-1271
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Based on https://github.com/coinbase/smart-wallet/blob/main/src/ERC1271.sol
 * @notice Abstract ERC-1271 implementation (based on Solady's) with guards to handle the same
 *       signer being used on multiple accounts.
 */
abstract contract ERC1271 is EIP712 {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev We use `bytes32 hash` rather than `bytes message`
     * In the EIP-712 context, `bytes message` would be useful for showing users a full message
     * they are signing in some wallet preview. But in this case, to prevent replay
     * across accounts, we are always dealing with nested messages, and so the
     * input should be a EIP-191 or EIP-712 output hash.
     * E.g. The input hash would be result of
     *
     *  keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
     *
     *  OR
     *
     * keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage),
     */
    bytes32 private constant _MESSAGE_TYPEHASH = keccak256("SplitMessage(bytes32 hash)");

    /// @dev EIP-712 domain typehash without chainId. Signatures over this domain are valid on every
    ///      chain where this account exists at the same address (guaranteed by CREATE2 deployment).
    bytes32 private constant _CHAINLESS_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,address verifyingContract)");

    /// @dev Discriminator prefix for ERC-1271 signature blobs. SPIKE NOTE: breaking change — v1.0
    ///      blobs carry no prefix byte.
    bytes1 private constant _SIG_DOMAIN_CHAIN_BOUND = 0x00;
    bytes1 private constant _SIG_DOMAIN_CHAINLESS = 0x01;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Initializes the {EIP712} domain separator.
     */
    constructor(string memory name_, string memory version_) EIP712(name_, version_) { }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the `signature` against the given `hash`.
     *
     * @dev This implementation follows ERC-1271. See https://eips.ethereum.org/EIPS/eip-1271.
     * @dev IMPORTANT: Signature verification is performed on the hash produced AFTER applying the anti
     *      cross-account-replay layer on the given `hash` (i.e., verification is run on the replay-safe
     *      hash version).
     *
     * @param hash_      The original hash.
     * @param signature_ The signature of the replay-safe hash to validate.
     * @return result `0x1626ba7e` if validation succeeded, else `0xffffffff`.
     */
    function isValidSignature(bytes32 hash_, bytes calldata signature_) public view virtual returns (bytes4) {
        bytes32 digest = signature_[0] == _SIG_DOMAIN_CHAINLESS ? chainlessReplaySafeHash(hash_) : replaySafeHash(hash_);

        if (_isValidSignature(digest, signature_[1:])) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /**
     * @dev Returns an EIP-712-compliant hash of `hash`,
     * where the domainSeparator includes address(this) and block.chainId
     * to protect against the same signature being used for many accounts.
     *
     * @param hash_ The original hash.
     * @return
     *  keccak256(\x19\x01 || this.domainSeparator ||
     *      hashStruct(SplitWalletMessage({
     *          hash: `hash`
     *      }))
     *  )
     */
    function replaySafeHash(bytes32 hash_) public view virtual returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_MESSAGE_TYPEHASH, hash_)));
    }

    /**
     * @dev Chain-agnostic sibling of `replaySafeHash`: same SplitMessage struct, but the domain
     *      omits chainId so one signature verifies on every chain. Cross-account replay protection
     *      is preserved via `verifyingContract`. Shared by the ChainlessUserOp validation path and
     *      the chainless ERC-1271 flow.
     *
     * @param hash_ The original hash.
     */
    function chainlessReplaySafeHash(bytes32 hash_) public view virtual returns (bytes32) {
        return _hashChainlessTypedData(keccak256(abi.encode(_MESSAGE_TYPEHASH, hash_)));
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the `signature` against the given `hash`.
     *
     * @dev MUST be defined by the implementation.
     *
     * @param hash_      The hash whose signature has been performed on.
     * @param signature_ The signature associated with `hash`.
     * @return `true` is the signature is valid, else `false`.
     */
    function _isValidSignature(bytes32 hash_, bytes calldata signature_) internal view virtual returns (bool);

    /// @dev Hashes `structHash` into the chainless (no chainId) EIP-712 domain.
    function _hashChainlessTypedData(bytes32 structHash_) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(
            keccak256(
                abi.encode(
                    _CHAINLESS_DOMAIN_TYPEHASH,
                    keccak256(bytes(_EIP712Name())),
                    keccak256(bytes(_EIP712Version())),
                    address(this)
                )
            ),
            structHash_
        );
    }
}
