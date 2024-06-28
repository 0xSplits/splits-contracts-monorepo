// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title ERC-1271
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

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Initializes the {EIP712} domain separator.
     */
    constructor(string memory _name, string memory _version) EIP712(_name, _version) { }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the `signature` against the given `hash`.
     * @dev This implementation follows ERC-1271. See https://eips.ethereum.org/EIPS/eip-1271.
     * @dev IMPORTANT: Signature verification is performed on the hash produced AFTER applying the anti
     *      cross-account-replay layer on the given `hash` (i.e., verification is run on the replay-safe
     *      hash version).
     * @param _hash      The original hash.
     * @param _signature The signature of the replay-safe hash to validate.
     * @return result `0x1626ba7e` if validation succeeded, else `0xffffffff`.
     */
    function isValidSignature(bytes32 _hash, bytes calldata _signature) public view virtual returns (bytes4) {
        if (_isValidSignature(replaySafeHash(_hash), _signature)) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /**
     * @dev Returns an EIP-712-compliant hash of `hash`,
     * where the domainSeparator includes address(this) and block.chainId
     * to protect against the same signature being used for many accounts.
     * @return
     *  keccak256(\x19\x01 || this.domainSeparator ||
     *      hashStruct(SplitWalletMessage({
     *          hash: `hash`
     *      }))
     *  )
     */
    function replaySafeHash(bytes32 _hash) public view virtual returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_MESSAGE_TYPEHASH, _hash)));
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the `signature` against the given `hash`.
     * @dev MUST be defined by the implementation.
     * @param _hash      The hash whose signature has been performed on.
     * @param _signature The signature associated with `hash`.
     * @return `true` is the signature is valid, else `false`.
     */
    function _isValidSignature(bytes32 _hash, bytes calldata _signature) internal view virtual returns (bool);
}
