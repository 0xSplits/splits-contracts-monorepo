// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "./MultiSignerLib.sol";

/**
 * @title Multi Signer signature library
 * @author Splits
 */
library MultiSignerSignatureLib {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Thrown when trying to access an empty signer.
     * @param index Index of the empty signer.
     */
    error SignerNotPresent(uint8 index);

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    // Size in bytes allocated for each signer in the data structure.
    uint256 public constant SIGNER_SIZE = 66;

    // Signer type representing an externally owned account (EOA) signer.
    uint8 public constant EOA_SIGNER_TYPE = 1;

    // Signer type representing a passkey-based signer.
    uint8 public constant PASSKEY_SIGNER_TYPE = 2;

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
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ abi.encode(SignatureWrapper[])
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
        isValid = true;

        uint8 threshold = $_.threshold;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        for (uint256 i; i < threshold; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                MultiSignerLib.isValidSignature(hash_, $_.signers[signerIndex], signatures_[i].signatureData)
                    && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }
    }

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$` and 'signers_`.
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ abi.encode(SignatureWrapper[]).
     * @param signerUpdates_ list of signer additions made to the signer set.
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes32 hash_,
        SignatureWrapper[] memory signatures_,
        bytes memory signerUpdates_
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
        bytes memory signer;
        for (uint256 i; i < threshold; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            signer = $_.signers[signerIndex];

            if (signer.length == 0) {
                signer = getSignerAtIndex(signerUpdates_, signatures_[i].signerIndex);
            }

            if (
                MultiSignerLib.isValidSignature(hash_, signer, signatures_[i].signatureData)
                    && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }
    }

    function getSignerAtIndex(bytes memory signerUpdates_, uint8 index_) internal pure returns (bytes memory signer) {
        uint256 numUpdates = signerUpdates_.length;

        uint8 currentIndex;
        for (uint256 i = 0; i < numUpdates; i += SIGNER_SIZE) {
            assembly {
                currentIndex := byte(0, mload(add(signerUpdates_, add(32, i))))
            }

            if (currentIndex == index_) {
                uint8 signerType;
                uint256 returnLength;

                assembly {
                    signerType := byte(0, mload(add(add(signerUpdates_, add(32, i)), 1)))
                }

                if (signerType == EOA_SIGNER_TYPE) {
                    returnLength = MultiSignerLib.EOA_SIGNER_SIZE;
                } else if (signerType == PASSKEY_SIGNER_TYPE) {
                    returnLength = MultiSignerLib.PASSKEY_SIGNER_SIZE;
                }

                signer = new bytes(returnLength);
                assembly {
                    let dataPtr := add(add(signerUpdates_, i), 34) // Skip index and signer type bytes
                    let destPtr := add(signer, 32)

                    switch returnLength
                    case 32 { mstore(destPtr, mload(dataPtr)) }
                    case 64 {
                        mstore(destPtr, mload(dataPtr))
                        mstore(add(destPtr, 32), mload(add(dataPtr, 32)))
                    }
                }
                return signer;
            }
        }

        revert SignerNotPresent(index_);
    }
}
