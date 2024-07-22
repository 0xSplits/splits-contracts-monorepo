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

    function _processSignerSetUpdates(SignerSetUpdate[] memory _signerUpdates) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 numUpdates = _signerUpdates.length;
        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdate(_signerUpdates[i]);
            $.nonce += 1;
            emit updateNonce($.nonce);
            _processSignerSetUpdate(_signerUpdates[i]);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdate(SignerSetUpdate memory _signerUpdate) internal view {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        if (
            !MultiSignerSignatureLib.isValidSignature(
                $, _getSignerUpdateHash(_signerUpdate, $.nonce), _signerUpdate.normalSignature
            )
        ) revert SignerSetUpdateValidationFailed(_signerUpdate);
    }

    function _processSignerSetUpdate(SignerSetUpdate memory _signerUpdate) internal {
        SignerUpdateParam[] memory updateParams = _signerUpdate.updateParams;
        uint256 numUpdates = updateParams.length;
        for (uint256 i; i < numUpdates; i++) {
            _processSignerUpdateParam(updateParams[i]);
        }
    }

    function _processSignerSetUpdatesMemory(SignerSetUpdate[] memory _signerUpdates)
        internal
        view
        returns (bytes[256] memory signers, uint8 threshold)
    {
        uint256 nonce = _getMultiSignerStorage().nonce;
        uint256 numUpdates = _signerUpdates.length;
        threshold = getThreshold();
        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdateMemory(_signerUpdates[i], signers, threshold, nonce++);
            (signers, threshold) = _processSignerSetUpdateMemory(_signerUpdates[i], signers, threshold);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdateMemory(
        SignerSetUpdate memory _signerUpdate,
        bytes[256] memory _signers,
        uint8 _threshold,
        uint256 _nonce
    )
        internal
        view
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        if (
            !MultiSignerSignatureLib.isValidSignature({
                $: $,
                _signers: _signers,
                _threshold: _threshold,
                _hash: _getSignerUpdateHash(_signerUpdate, _nonce),
                _signature: _signerUpdate.normalSignature
            })
        ) {
            revert SignerSetUpdateValidationFailed(_signerUpdate);
        }
    }

    function _processSignerSetUpdateMemory(
        SignerSetUpdate memory _signerUpdate,
        bytes[256] memory _signers,
        uint8 _threshold
    )
        internal
        view
        returns (bytes[256] memory, uint8)
    {
        SignerUpdateParam[] memory updateParams = _signerUpdate.updateParams;
        uint256 numUpdates = updateParams.length;

        for (uint256 i; i < numUpdates; i++) {
            SignerUpdateParam memory _signerUpdateParam = updateParams[i];
            if (_signerUpdateParam.updateType == SignerUpdateType.AddSigner) {
                (bytes memory signer, uint8 index) = abi.decode(_signerUpdateParam.data, (bytes, uint8));
                MultiSignerLib.validateSigner(signer);
                _signers[index] = signer;
            } else if (_signerUpdateParam.updateType == SignerUpdateType.RemoveSigner) {
                uint8 index = abi.decode(_signerUpdateParam.data, (uint8));
                _signers[index] = bytes.concat(MultiSignerSignatureLib.SIGNER_REMOVED);
            } else if (_signerUpdateParam.updateType == SignerUpdateType.UpdateThreshold) {
                _threshold = abi.decode(_signerUpdateParam.data, (uint8));
            } else {
                revert InvalidSignerUpdateParam(_signerUpdateParam);
            }
        }

        return (_signers, _threshold);
    }

    function _processSignerUpdateParam(SignerUpdateParam memory _signerUpdateParam) internal {
        if (_signerUpdateParam.updateType == SignerUpdateType.AddSigner) {
            (bytes memory signer, uint8 index) = abi.decode(_signerUpdateParam.data, (bytes, uint8));
            _addSigner(signer, index);
        } else if (_signerUpdateParam.updateType == SignerUpdateType.RemoveSigner) {
            uint8 index = abi.decode(_signerUpdateParam.data, (uint8));
            _removeSigner(index);
        } else if (_signerUpdateParam.updateType == SignerUpdateType.UpdateThreshold) {
            uint8 threshold_ = abi.decode(_signerUpdateParam.data, (uint8));
            _updateThreshold(threshold_);
        } else {
            revert InvalidSignerUpdateParam(_signerUpdateParam);
        }
    }

    function _getSignerUpdateHash(
        SignerSetUpdate memory _signerSetUpdate,
        uint256 _nonce
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(_nonce, address(this), _signerSetUpdate.updateParams));
    }
}
