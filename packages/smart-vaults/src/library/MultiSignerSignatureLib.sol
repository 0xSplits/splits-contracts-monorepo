// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "./MultiSignerLib.sol";

/**
 * @title Multi Signer signature library
 * @author Splits
 */
library MultiSignerSignatureLib {
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

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$_`
     *
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ List of signatureWrapper
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
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
        MultiSignerLib.MultiSignerStorage storage $_,
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
                MultiSignerLib.isValidSignature(frontHash_, $_.signers[signerIndex], signatures_[i].signatureData)
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
            MultiSignerLib.isValidSignature(backHash_, $_.signers[signerIndex], signatures_[i].signatureData)
                && alreadySigned & mask == 0
        ) {
            alreadySigned |= mask;
        } else {
            isValid = false;
        }
    }
}
