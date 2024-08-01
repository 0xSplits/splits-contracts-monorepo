// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { WebAuthn } from "@web-authn/WebAuthn.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title Multi Signer Library
 * @author Splits
 */
library MultiSignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    // Size in bytes for an externally owned account (EOA) signer.
    uint256 public constant EOA_SIGNER_SIZE = 32;

    // Size in bytes for a passkey-based signer.
    uint256 public constant PASSKEY_SIGNER_SIZE = 64;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Storage layout used by this contract.
    /// @dev Can allow up to 256 signers.
    /// @custom:storage-location erc7201:splits.storage.MultiSigner
    struct MultiSignerStorage {
        uint256 nonce;
        /// @dev Number of unique signatures required to validate a message signed by this contract.
        uint8 threshold;
        /// @dev number of signers
        uint8 signerCount;
        /// @dev signer bytes;
        mapping(uint8 => bytes) signers;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Thrown when a provided signer is neither 64 bytes long (for public key)
     *         nor a ABI encoded address.
     * @param signer The invalid signer.
     */
    error InvalidSignerBytesLength(bytes signer);

    /**
     * @notice Thrown if a provided signer is 32 bytes long but does not fit in an `address` type or if `signer` has
     * code.
     * @param signer The invalid signer.
     */
    error InvalidEthereumAddressOwner(bytes signer);

    /// @notice Thrown when threshold is greater than number of owners or when zero.
    error InvalidThreshold();

    /// @notice Thrown when number of signers is more than 256.
    error InvalidNumberOfSigners();

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the list of `signers` and `threshold`.
     * @dev Throws error when number of signers is zero or greater than 255.
     * @dev Throws error if `threshold` is zero or greater than number of signers.
     * @param signers_ abi encoded list of signers (passkey/eoa).
     * @param threshold_ minimum number of signers required for approval.
     */
    function validateSigners(bytes[] calldata signers_, uint8 threshold_) internal view {
        if (signers_.length > 255 || signers_.length == 0) revert InvalidNumberOfSigners();

        uint8 numberOfSigners = uint8(signers_.length);

        if (numberOfSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        bytes memory signer;

        for (uint8 i; i < numberOfSigners; i++) {
            signer = signers_[i];

            validateSigner(signer);
        }
    }

    /**
     * @notice Validates the signer.
     * @dev Throws error when length of signer is neither 32 or 64.
     * @dev Throws error if signer is invalid address or if address has code.
     */
    function validateSigner(bytes memory signer_) internal view {
        if (signer_.length != EOA_SIGNER_SIZE && signer_.length != PASSKEY_SIGNER_SIZE) {
            revert InvalidSignerBytesLength(signer_);
        }

        if (signer_.length == EOA_SIGNER_SIZE) {
            if (uint256(bytes32(signer_)) > type(uint160).max) revert InvalidEthereumAddressOwner(signer_);
            address eoa;
            assembly ("memory-safe") {
                eoa := mload(add(signer_, 32))
            }
        }
    }

    /**
     * @notice validates if the signature provided by the signer at `signerIndex` is valid for the hash.
     */
    function isValidSignature(
        bytes32 hash_,
        bytes memory signer_,
        bytes memory signature_
    )
        internal
        view
        returns (bool isValid)
    {
        if (signer_.length == EOA_SIGNER_SIZE) {
            isValid = isValidSignatureEOA(hash_, signer_, signature_);
        } else if (signer_.length == PASSKEY_SIGNER_SIZE) {
            isValid = isValidSignaturePasskey(hash_, signer_, signature_);
        }
    }

    function isValidSignaturePasskey(
        bytes32 hash_,
        bytes memory signer_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        (uint256 x, uint256 y) = abi.decode(signer_, (uint256, uint256));

        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature_, (WebAuthn.WebAuthnAuth));

        return WebAuthn.verify({ challenge: abi.encode(hash_), requireUV: false, webAuthnAuth: auth, x: x, y: y });
    }

    function isValidSignatureEOA(
        bytes32 hash_,
        bytes memory signer_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        address owner;
        assembly ("memory-safe") {
            owner := mload(add(signer_, 32))
        }

        return SignatureCheckerLib.isValidSignatureNow(owner, hash_, signature_);
    }
}
