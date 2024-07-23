// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "./MultiSignerLib.sol";

/**
 * @title Multi Signer signature library
 * @author Splits
 */
library MultiSignerSignatureLib {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Identify if the signer has been removed from the signer set.
    /// @dev keccak256("removed")
    bytes32 public constant SIGNER_REMOVED = 0xb04ab4afa2f1583231336fc5be76c590578027387608a6a8dc2e65a46dbe66d3;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    struct SignatureWrapper {
        /// @dev The index of the signer that signed, see `MultiSigner.signerAtIndex`
        uint8 signerIndex;
        /**
         * @dev If `MultiSigner.signerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
         *      If `MultiSigner.signerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
         */
        bytes signatureData;
    }

    /// signature data required to verify if given data is signed by the signer set present in MultiSigner.
    struct Signature {
        SignatureWrapper[] signature;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$_` for a given threshold.
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param threshold_ Number of required valid signatures.
     * @param signatures_ List of SignatureWrapper.
     * @param alreadySigned_ signers whose signature won't be accepted as valid.
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes32 hash_,
        uint8 threshold_,
        SignatureWrapper[] memory signatures_,
        uint256 alreadySigned_
    )
        internal
        view
        returns (bool isValid, uint256)
    {
        isValid = true;
        uint256 mask;
        uint8 signerIndex;
        for (uint256 i; i < threshold_; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                MultiSignerLib.isValidSignature(hash_, $_.signers[signerIndex], signatures_[i].signatureData)
                    && (alreadySigned_ & mask == 0)
            ) {
                alreadySigned_ |= mask;
            } else {
                isValid = false;
            }
        }
        return (isValid, alreadySigned_);
    }

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$` and 'signers_`.
     * @param $_ Storage reference to MultiSigner storage.
     * @param signers_ list of 256 possible signers. Has higher preference over signers present in storage at a given
     * index.
     * @param threshold_ Number of required valid signatures.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ List of SignatureWrapper.
     * @param alreadySigned_ signers whose signature won't be accepted as valid.
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes[256] memory signers_,
        uint8 threshold_,
        bytes32 hash_,
        SignatureWrapper[] memory signatures_,
        uint256 alreadySigned_
    )
        internal
        view
        returns (bool isValid, uint256)
    {
        isValid = true;
        uint256 mask;
        uint8 signerIndex;
        bytes memory signer;
        for (uint256 i; i < threshold_; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            signer = signers_[signerIndex];
            if (signer.length == 0) {
                signer = $_.signers[signerIndex];
            } else if (bytes32(signer) == SIGNER_REMOVED) {
                isValid = false;
            }

            if (
                MultiSignerLib.isValidSignature(hash_, signer, signatures_[i].signatureData)
                    && (alreadySigned_ & mask == 0)
            ) {
                alreadySigned_ |= mask;
            } else {
                isValid = false;
            }
        }
        return (isValid, alreadySigned_);
    }

    /**
     * @notice validates if `hash_` was signed by the signer present in `$_`.
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signature_ SignatureWrapper.
     * @param alreadySigned_ signers whose signature won't be accepted as valid.
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes32 hash_,
        SignatureWrapper memory signature_,
        uint256 alreadySigned_
    )
        internal
        view
        returns (bool)
    {
        uint8 signerIndex = signature_.signerIndex;

        return (
            MultiSignerLib.isValidSignature(hash_, $_.signers[signerIndex], signature_.signatureData)
                && (alreadySigned_ & (1 << signerIndex)) == 0
        );
    }
}
