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

    uint256 public constant SIGNER_SIZE = 65;
    uint8 public constant EMPTY_SIGNER_TYPE = 0;
    uint8 public constant EOA_SIGNER_TYPE = 1;
    uint8 public constant PASSKEY_SIGNER_TYPE = 2;
    uint8 public constant REMOVED_SIGNER_TYPE = 3;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidSignerType(uint8 signerType);

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
        SignatureWrapper[] signatures;
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
        returns (bool isValid)
    {
        isValid = true;

        Signature memory signature = abi.decode(signature_, (Signature));
        SignatureWrapper[] memory signatures = signature.signatures;

        uint8 threshold = $_.threshold;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        for (uint256 i; i < threshold; i++) {
            signerIndex = signatures[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                MultiSignerLib.isValidSignature(hash_, $_.signers[signerIndex], signatures[i].signatureData)
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
     * @param signers_ list of 256 possible signers. Has higher preference over signers present in storage at a given
     * index.
     * @param threshold_ signer set threshold used for verification.
     * @param hash_ blob of data that needs to be verified.
     * @param signature_ abi.encode(Signature)
     */
    function isValidSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        bytes memory signers_,
        uint8 threshold_,
        bytes32 hash_,
        bytes memory signature_
    )
        internal
        view
        returns (bool isValid)
    {
        isValid = true;

        Signature memory signature = abi.decode(signature_, (Signature));
        SignatureWrapper[] memory signatures = signature.signatures;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bytes memory signer;
        uint8 signerType;
        for (uint256 i; i < threshold_; i++) {
            signerIndex = signatures[i].signerIndex;
            mask = (1 << signerIndex);

            (signer, signerType) = getSignerAtIndex(signers_, signatures[i].signerIndex);

            if (signerType == EMPTY_SIGNER_TYPE) {
                signer = $_.signers[signerIndex];
            } else if (signerType == REMOVED_SIGNER_TYPE) {
                isValid = false;
            }

            if (
                MultiSignerLib.isValidSignature(hash_, signer, signatures[i].signatureData) && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }
    }

    function getSignerAtIndex(bytes memory signers_, uint8 index_) internal pure returns (bytes memory, uint8) {
        uint256 start = uint256(index_) * SIGNER_SIZE;

        uint8 signerType;
        assembly {
            signerType := byte(0, mload(add(signers_, add(32, start))))
        }

        uint256 returnLength;
        if (signerType == EMPTY_SIGNER_TYPE || signerType == REMOVED_SIGNER_TYPE) {
            return (new bytes(0), signerType);
        } else if (signerType == EOA_SIGNER_TYPE) {
            returnLength = MultiSignerLib.EOA_SIGNER_SIZE;
        } else if (signerType == PASSKEY_SIGNER_TYPE) {
            returnLength = MultiSignerLib.PASSKEY_SIGNER_SIZE;
        } else {
            revert InvalidSignerType(signerType);
        }

        bytes memory signer = new bytes(returnLength);

        assembly {
            let dataPtr := add(add(signers_, 33), start)
            let itemPtr := add(signer, 32)

            switch returnLength
            case 32 { mstore(itemPtr, mload(dataPtr)) }
            case 64 {
                mstore(itemPtr, mload(dataPtr))
                mstore(add(itemPtr, 32), mload(add(dataPtr, 32)))
            }
        }

        return (signer, signerType);
    }
}
