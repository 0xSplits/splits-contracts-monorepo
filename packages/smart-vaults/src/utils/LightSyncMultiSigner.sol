// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { MultiSignerSignatureLib } from "../library/MultiSignerSignatureLib.sol";

import { MultiSigner } from "./MultiSigner.sol";
import { WebAuthn } from "@web-authn/WebAuthn.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title Multi Signer with light state sync functionality.
 * @author Splits
 */
abstract contract LightSyncMultiSigner is MultiSigner {
    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Signer set update.
    struct SignerSetUpdate {
        // bitpack
        /**
           // doesn't match the code which is (bytes, uint8)
         * AddSigner: abi.encode(uint8 index, uint8 signerType, bytes signer)
         * AddSigner: uint8 index || uint8 signerType || bytes signer
         */
        bytes data;
        /// abi.encode(MultiSignerSignatureLib.SignatureWrapper[]) signature over keccak256(nonce, address(this), data).
        bytes normalSignature;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */


    /**
     * @notice Thrown when signer signer set update signature validation fails.
     * @param _signerSetUpdate Signer set update that failed validation.
     */
    error SignerSetUpdateValidationFailed(SignerSetUpdate _signerSetUpdate);

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /// @dev only called when there is a light sync state update. It is expected that signerUpdates_.length > 0.
    function _processSignerSetUpdates(SignerSetUpdate[] memory signerUpdates_) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;
        uint256 numUpdates = signerUpdates_.length;
        for (uint256 i; i < numUpdates; i++) {
            _isValidSignerSetUpdateSignature($, signerUpdates_[i], nonce++);
            _processSignerSetUpdate(signerUpdates_[i]);
        }
        $.nonce = nonce;
        emit updateNonce(nonce);
    }

    /// @dev reverts if validation fails.
    function _isValidSignerSetUpdateSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        SignerSetUpdate memory signerSetUpdate_,
        uint256 nonce_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature(
                $_, _getSignerUpdateHash(signerSetUpdate_, nonce_), signerSetUpdate_.normalSignature
            )
        ) revert SignerSetUpdateValidationFailed(signerSetUpdate_);
    }

    function _processSignerSetUpdate(SignerSetUpdate memory signerSetUpdate_) internal {
        (bytes memory signer, uint8 index) = abi.decode(signerSetUpdate_.data, (bytes, uint8));
        _addSigner(signer, index);
    }

    function _processSignerSetUpdatesMemory(SignerSetUpdate[] memory signerSetUpdates_)
        internal
        view
        returns (bytes memory signerUpdates)
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;

        uint256 numUpdates = signerSetUpdates_.length;
        signerUpdates = new bytes(MultiSignerSignatureLib.SIGNER_SIZE * numUpdates);

        uint256 signerAddedBitMap;

        for (uint256 i; i < numUpdates; i++) {
            _isValidSignerSetUpdateSignature({
                $_: $,
                signerSetUpdate_: signerSetUpdates_[i],
                signerUpdates_: signerUpdates,
                nonce_: nonce++
            });
            signerAddedBitMap = _processSignerSetUpdateMemory({
                insertIndex_: i,
                signerSetUpdate_: signerSetUpdates_[i],
                signerAddedBitMap_: signerAddedBitMap,
                signerUpdates_: signerUpdates
            });
        }
    }

    /// @notice reverts if validation fails
    function _isValidSignerSetUpdateSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        SignerSetUpdate memory signerSetUpdate_,
        bytes memory signerUpdates_,
        uint256 nonce_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature({
                $_: $_,
                signerUpdates_: signerUpdates_,
                hash_: _getSignerUpdateHash(signerSetUpdate_, nonce_),
                signature_: signerSetUpdate_.normalSignature
            })
        ) {
            revert SignerSetUpdateValidationFailed(signerSetUpdate_);
        }
    }

    // can revisit this after we settle on the storage / packing stuff
    function _processSignerSetUpdateMemory(
        uint256 insertIndex_,
        SignerSetUpdate memory signerSetUpdate_,
        uint256 signerAddedBitMap_,
        bytes memory signerUpdates_
    )
        internal
        view
        returns (uint256)
    {
        (bytes memory signer, uint8 index) = abi.decode(signerSetUpdate_.data, (bytes, uint8));
        MultiSignerLib.validateSigner(signer);

        uint256 bitMask = 1 << index;
        if (signerAddedBitMap_ & bitMask != 0) {
            revert SignerAlreadyPresent(index);
        }
        signerAddedBitMap_ = signerAddedBitMap_ | bitMask;

        uint8 signerType;
        if (signer.length == MultiSignerLib.EOA_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.EOA_SIGNER_TYPE;
        } else if (signer.length == MultiSignerLib.PASSKEY_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.PASSKEY_SIGNER_TYPE;
        }

        // this is memory safe right?
        assembly {
            let destPtr := add(add(signerUpdates_, 32), mul(insertIndex_, 66))
            mstore8(destPtr, index)
            mstore8(add(destPtr, 1), signerType)

            let dataPtr := add(signer, 32)

            switch signerType
            case 1 { mstore(add(destPtr, 2), mload(dataPtr)) }
            case 2 {
                mstore(add(destPtr, 2), mload(dataPtr)) // Copy first 32 bytes
                mstore(add(destPtr, 34), mload(add(dataPtr, 32))) // Copy second 32 bytes
            }
        }

        return signerAddedBitMap_;
    }

    function _getSignerUpdateHash(
        SignerSetUpdate memory signerSetUpdate_,
        uint256 nonce_
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(nonce_, address(this), signerSetUpdate_.data));
    }
}
