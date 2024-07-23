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
     * @notice validates if `hash_` was signed by the signer set present in `$_`
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signature_ abi.encode(Signature)
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes32 hash_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        Signature memory signature = abi.decode(signature_, (Signature));
        SignatureWrapper[] memory sigWrappers = signature.signature;

        uint8 threshold = $_.threshold;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        for (uint256 i; i < threshold; i++) {
            signerIndex = sigWrappers[i].signerIndex;
            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) return false;

            if (MultiSignerLib.isValidSignature(hash_, $_.signers[signerIndex], sigWrappers[i].signatureData)) {
                alreadySigned |= mask;
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$` and 'signers_`.
     * @param $_ Storage reference to MultiSigner storage.
     * @param signers_ list of 256 possible signers. Has higher preference over signers present in storage at a given
     * index.
     * @param threshold_ signer set threshold used for verification.
     * @param hash_ blob of data that needs to be verified.
     * @param signature_ abi.encode(Signature)
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes[256] memory signers_,
        uint8 threshold_,
        bytes32 hash_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        Signature memory signature = abi.decode(signature_, (Signature));
        SignatureWrapper[] memory sigWrappers = signature.signature;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bytes memory signer;
        for (uint256 i; i < threshold_; i++) {
            signerIndex = sigWrappers[i].signerIndex;
            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) return false;

            signer = signers_[signerIndex];
            if (signer.length == 0) {
                signer = $_.signers[signerIndex];
            } else if (bytes32(signer) == SIGNER_REMOVED) {
                return false;
            }

            if (MultiSignerLib.isValidSignature(hash_, signer, sigWrappers[i].signatureData)) {
                alreadySigned |= mask;
            } else {
                return false;
            }
        }
        return true;
    }
}
