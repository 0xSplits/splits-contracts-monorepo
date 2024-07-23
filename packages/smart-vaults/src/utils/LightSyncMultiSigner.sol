// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { MultiSignerSignatureLib } from "../library/MultiSignerSignatureLib.sol";

import { MultiSigner } from "./MultiSigner.sol";
import { WebAuthn } from "@web-authn/WebAuthn.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title Multi Signer with light state sync functionality
 * @author Splits
 */
abstract contract LightSyncMultiSigner is MultiSigner {
    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Signer Update types
    enum SignerUpdateType {
        /// Adds a new signer to the signer set.
        AddSigner,
        /// Removes a signer from the signer set.
        RemoveSigner,
        /// Updates signer set threshold.
        UpdateThreshold
    }

    /// @notice Signer Update parameters
    struct SignerUpdateParam {
        /// Type of update
        SignerUpdateType updateType;
        /**
         * Data can be of the following types:
         *  AddSigner: abi.encode(bytes signer, uint8 index)
         *  RemoveSigner: abi.encode(uint8 index)
         *  UpdateThreshold: abi.encode(uint8 threshold)
         */
        bytes data;
    }

    /// @notice Signer set update
    struct SignerSetUpdate {
        /// List of updates to the signer set.
        SignerUpdateParam[] updateParams;
        /// abi.encode(MultiSignerSignatureLib.Signature) signature over keccak256(nonce, address(this), updateParams)
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
        uint256 numUpdates = signerUpdates_.length;
        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdate(signerUpdates_[i]);
            $.nonce += 1;
            emit updateNonce($.nonce);
            _processSignerSetUpdate(signerUpdates_[i]);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdate(SignerSetUpdate memory signerUpdate_) internal view {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        (bool isValid,) = MultiSignerSignatureLib.isValidSignature({
            $_: $,
            threshold_: $.threshold,
            hash_: _getSignerUpdateHash(signerUpdate_, $.nonce),
            signatures_: abi.decode(signerUpdate_.normalSignature, (MultiSignerSignatureLib.Signature)).signature,
            alreadySigned_: 0
        });
        if (!isValid) revert SignerSetUpdateValidationFailed(signerUpdate_);
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
        returns (bytes[256] memory signers, uint8 threshold)
    {
        uint256 nonce = _getMultiSignerStorage().nonce;
        uint256 numUpdates = signerUpdates_.length;
        threshold = getThreshold();
        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdateMemory(signerUpdates_[i], signers, threshold, nonce++);
            (signers, threshold) = _processSignerSetUpdateMemory(signerUpdates_[i], signers, threshold);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdateMemory(
        SignerSetUpdate memory signerUpdate_,
        bytes[256] memory signers_,
        uint8 threshold_,
        uint256 nonce_
    )
        internal
        view
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();

        (bool isValid,) = MultiSignerSignatureLib.isValidSignature({
            $_: $,
            signers_: signers_,
            threshold_: threshold_,
            hash_: _getSignerUpdateHash(signerUpdate_, nonce_),
            signatures_: abi.decode(signerUpdate_.normalSignature, (MultiSignerSignatureLib.Signature)).signature,
            alreadySigned_: 0
        });
        if (!isValid) {
            revert SignerSetUpdateValidationFailed(signerUpdate_);
        }
    }

    function _processSignerSetUpdateMemory(
        SignerSetUpdate memory signerUpdate_,
        bytes[256] memory signers_,
        uint8 threshold_
    )
        internal
        view
        returns (bytes[256] memory, uint8)
    {
        SignerUpdateParam[] memory updateParams = signerUpdate_.updateParams;
        uint256 numUpdates = updateParams.length;

        SignerUpdateParam memory signerUpdateParam;
        for (uint256 i; i < numUpdates; i++) {
            signerUpdateParam = updateParams[i];
            if (signerUpdateParam.updateType == SignerUpdateType.AddSigner) {
                (bytes memory signer, uint8 index) = abi.decode(signerUpdateParam.data, (bytes, uint8));
                MultiSignerLib.validateSigner(signer);
                signers_[index] = signer;
            } else if (signerUpdateParam.updateType == SignerUpdateType.RemoveSigner) {
                uint8 index = abi.decode(signerUpdateParam.data, (uint8));
                signers_[index] = bytes.concat(MultiSignerSignatureLib.SIGNER_REMOVED);
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
