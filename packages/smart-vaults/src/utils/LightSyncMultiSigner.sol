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

    /// @notice Signer Update types.
    enum SignerUpdateType {
        /// Adds a new signer to the signer set.
        AddSigner,
        /// Removes a signer from the signer set.
        RemoveSigner,
        /// Updates signer set threshold.
        UpdateThreshold
    }

    /// @notice Signer Update parameters.
    struct SignerUpdateParam {
        /// Type of update.
        SignerUpdateType updateType;
        /**
         * Data can be of the following types:
         *  AddSigner: abi.encode(bytes signer, uint8 index)
         *  RemoveSigner: abi.encode(uint8 index)
         *  UpdateThreshold: abi.encode(uint8 threshold)
         */
        bytes data;
    }

    /// @notice Signer set update.
    struct SignerSetUpdate {
        /// List of updates to the signer set.
        SignerUpdateParam[] updateParams;
        /// abi.encode(MultiSignerSignatureLib.SignatureWrapper[]) signature over keccak256(nonce, address(this),
        /// updateParams).
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

    /**
     * @notice Thrown when signer update param is of invalid type.
     * @param _signerSetUpdateParam Signer set update param with invalid type.
     */
    error InvalidSignerUpdateParam(SignerUpdateParam _signerSetUpdateParam);

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function _processSignerSetUpdates(SignerSetUpdate[] memory signerUpdates_) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;
        uint256 numUpdates = signerUpdates_.length;
        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdate($, signerUpdates_[i], nonce++);
            _processSignerSetUpdate(signerUpdates_[i]);
        }
        $.nonce = nonce;
        emit updateNonce(nonce);
    }

    /// @dev reverts if validation fails.
    function _validateSignerSetUpdate(
        MultiSignerLib.MultiSignerStorage storage $_,
        SignerSetUpdate memory signerUpdate_,
        uint256 nonce_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature(
                $_, _getSignerUpdateHash(signerUpdate_, nonce_), signerUpdate_.normalSignature
            )
        ) revert SignerSetUpdateValidationFailed(signerUpdate_);
    }

    function _processSignerSetUpdate(SignerSetUpdate memory signerUpdate_) internal {
        SignerUpdateParam[] memory updateParams = signerUpdate_.updateParams;
        uint256 numUpdates = updateParams.length;
        for (uint256 i; i < numUpdates; i++) {
            _processSignerUpdateParam(updateParams[i]);
        }
    }

    function _processSignerSetUpdatesMemory(SignerSetUpdate[] memory signerUpdates_)
        internal
        view
        returns (bytes memory signers, uint8 threshold)
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;
        threshold = $.threshold;
        uint256 numUpdates = signerUpdates_.length;
        signers = new bytes(256 * MultiSignerSignatureLib.SIGNER_SIZE);

        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdateMemory({
                $_: $,
                signerUpdate_: signerUpdates_[i],
                signers_: signers,
                threshold_: threshold,
                nonce_: nonce++
            });
            (signers, threshold) = _processSignerSetUpdateMemory(signerUpdates_[i], signers, threshold);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdateMemory(
        MultiSignerLib.MultiSignerStorage storage $_,
        SignerSetUpdate memory signerUpdate_,
        bytes memory signers_,
        uint8 threshold_,
        uint256 nonce_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature({
                $_: $_,
                signers_: signers_,
                threshold_: threshold_,
                hash_: _getSignerUpdateHash(signerUpdate_, nonce_),
                signature_: signerUpdate_.normalSignature
            })
        ) {
            revert SignerSetUpdateValidationFailed(signerUpdate_);
        }
    }

    function _processSignerSetUpdateMemory(
        SignerSetUpdate memory signerUpdate_,
        bytes memory signers_,
        uint8 threshold_
    )
        internal
        view
        returns (bytes memory, uint8)
    {
        SignerUpdateParam[] memory updateParams = signerUpdate_.updateParams;
        uint256 numUpdates = updateParams.length;

        SignerUpdateParam memory signerUpdateParam;
        for (uint256 i; i < numUpdates; i++) {
            signerUpdateParam = updateParams[i];
            if (signerUpdateParam.updateType == SignerUpdateType.AddSigner) {
                (bytes memory signer, uint8 index) = abi.decode(signerUpdateParam.data, (bytes, uint8));
                MultiSignerLib.validateSigner(signer);

                uint8 signerType;
                if (signer.length == MultiSignerLib.EOA_SIGNER_SIZE) {
                    signerType = MultiSignerSignatureLib.EOA_SIGNER_TYPE;
                } else {
                    signerType = MultiSignerSignatureLib.PASSKEY_SIGNER_TYPE;
                }

                uint256 start = uint256(index) * MultiSignerSignatureLib.SIGNER_SIZE;
                assembly {
                    let dataPtr := add(signers_, add(32, start))
                    mstore8(dataPtr, signerType)

                    let newDataPtr := add(signer, 32)
                    mstore(add(dataPtr, 1), mload(newDataPtr))

                    if eq(signerType, 2) { mstore(add(dataPtr, 33), mload(add(newDataPtr, 32))) }
                }
            } else if (signerUpdateParam.updateType == SignerUpdateType.RemoveSigner) {
                uint8 index = abi.decode(signerUpdateParam.data, (uint8));
                uint8 signerType = MultiSignerSignatureLib.REMOVED_SIGNER_TYPE;

                uint256 start = uint256(index) * MultiSignerSignatureLib.SIGNER_SIZE;
                assembly {
                    let dataPtr := add(signers_, add(32, start))
                    mstore8(dataPtr, signerType)
                }
            } else if (signerUpdateParam.updateType == SignerUpdateType.UpdateThreshold) {
                threshold_ = abi.decode(signerUpdateParam.data, (uint8));
            } else {
                revert InvalidSignerUpdateParam(signerUpdateParam);
            }
        }

        return (signers_, threshold_);
    }

    function _processSignerUpdateParam(SignerUpdateParam memory signerUpdateParam_) internal {
        if (signerUpdateParam_.updateType == SignerUpdateType.AddSigner) {
            (bytes memory signer, uint8 index) = abi.decode(signerUpdateParam_.data, (bytes, uint8));
            _addSigner(signer, index);
        } else if (signerUpdateParam_.updateType == SignerUpdateType.RemoveSigner) {
            uint8 index = abi.decode(signerUpdateParam_.data, (uint8));
            _removeSigner(index);
        } else if (signerUpdateParam_.updateType == SignerUpdateType.UpdateThreshold) {
            uint8 threshold_ = abi.decode(signerUpdateParam_.data, (uint8));
            _updateThreshold(threshold_);
        } else {
            revert InvalidSignerUpdateParam(signerUpdateParam_);
        }
    }

    function _getSignerUpdateHash(
        SignerSetUpdate memory signerSetUpdate_,
        uint256 nonce_
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(nonce_, address(this), signerSetUpdate_.updateParams));
    }
}
