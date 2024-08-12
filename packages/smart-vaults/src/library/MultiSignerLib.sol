// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { decodeAccountSigner } from "../signers/AccountSigner.sol";
import { decodePasskeySigner } from "../signers/PasskeySigner.sol";

/**
 * @title Multi Signer Library
 * @author Splits (https://splits.org)
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
        /// @dev Number of unique signatures required to validate a message signed by this contract.
        uint8 threshold;
        /// @dev number of signers
        uint8 signerCount;
        /// @dev signer bytes;
        mapping(uint8 => bytes) signers;
    }

    struct SignatureWrapper {
        /// @dev The index of the signer that signed, see `MultiSigner.signerAtIndex`
        uint8 signerIndex;
        /**
         * @dev If `MultiSigner.signerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
         *      If `MultiSigner.signerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
         */
        bytes signatureData;
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
     *
     * @dev Throws error when number of signers is zero or greater than 255.
     * @dev Throws error if `threshold` is zero or greater than number of signers.
     *
     * @param signers_ abi encoded list of signers (passkey/eoa).
     * @param threshold_ minimum number of signers required for approval.
     */
    function validateSigners(bytes[] calldata signers_, uint8 threshold_) internal pure {
        if (signers_.length > 255 || signers_.length == 0) revert InvalidNumberOfSigners();

        uint8 numberOfSigners = uint8(signers_.length);

        if (numberOfSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        for (uint8 i; i < numberOfSigners; i++) {
            validateSigner(signers_[i]);
        }
    }

    /**
     * @notice Validates the signer.
     *
     * @dev Throws error when length of signer is neither 32 or 64.
     * @dev Throws error if signer is invalid address.
     */
    function validateSigner(bytes memory signer_) internal pure {
        if (signer_.length != EOA_SIGNER_SIZE && signer_.length != PASSKEY_SIGNER_SIZE) {
            revert InvalidSignerBytesLength(signer_);
        }

        if (signer_.length == EOA_SIGNER_SIZE) {
            if (uint256(bytes32(signer_)) > type(uint160).max) revert InvalidEthereumAddressOwner(signer_);
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
            isValid = decodeAccountSigner(signer_).isValidSignature(hash_, signature_);
        } else if (signer_.length == PASSKEY_SIGNER_SIZE) {
            isValid = decodePasskeySigner(signer_).isValidSignature(hash_, signature_);
        }
    }

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$_`
     *
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ List of signatureWrapper
     */
    function isValidSignature(
        MultiSignerStorage storage $_,
        bytes32 hash_,
        SignatureWrapper[] memory signatures_
    )
        internal
        view
        returns (bool isValid)
    {
        return isValidSignature($_, hash_, hash_, signatures_);
    }

    /**
     * @notice validates if a pair of hashes was signed by the signer set present in `$_` with in-memory updates
     *
     * @param $_ Storage reference to MultiSigner storage.
     * @param frontHash_ blob of data that should be signed by all but the last signer.
     * @param backHash_ blob of data that should be signed by the last signer.
     * @param signatures_ List of signatureWrapper
     */
    function isValidSignature(
        MultiSignerStorage storage $_,
        bytes32 frontHash_,
        bytes32 backHash_,
        SignatureWrapper[] memory signatures_
    )
        internal
        view
        returns (bool isValid)
    {
        isValid = true;

        uint8 threshold = $_.threshold;

        uint256 alreadySigned;

        uint256 mask;
        uint8 signerIndex;
        uint256 i;
        for (; i < threshold - 1; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                isValidSignature(frontHash_, $_.signers[signerIndex], signatures_[i].signatureData)
                    && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }

        signerIndex = signatures_[i].signerIndex;
        mask = (1 << signerIndex);

        if (
            isValidSignature(backHash_, $_.signers[signerIndex], signatures_[i].signatureData)
                && alreadySigned & mask == 0
        ) {
            alreadySigned |= mask;
        } else {
            isValid = false;
        }
    }
}
