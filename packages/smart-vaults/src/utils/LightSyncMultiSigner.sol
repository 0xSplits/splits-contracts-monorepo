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
        uint8 index;
        bytes signer;
    }

    /// @notice Light sync signature
    struct LightSyncSignature {
        SignerSetUpdate update;
        MultiSignerSignatureLib.SignatureWrapper[] signatures;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when setting nonce to less than the current storage nonce.
    error InvalidNonce();

    /**
     * @notice Thrown when signer signer set update signature validation fails.
     * @param lightSyncUpdate light sync signature that failed validation.
     */
    error LightSyncUpdateValidationFailed(LightSyncSignature lightSyncUpdate);

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Emitted when nonce is updated.
     * @param nonce The new nonce for the signer set.
     */
    event updateNonce(uint256 nonce);

    /* -------------------------------------------------------------------------- */
    /*                            PUBLIC VIEW FUNCTIONS                           */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns the nonce for the signer set
    function getNonce() public view virtual returns (uint256) {
        return _getMultiSignerStorage().nonce;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Updates nonce of the signer set.
     *
     * @dev Reverts if `nonce_` less than or equal to current nonce.
     *
     * @param nonce_ nonce to set.
     */
    function setNonce(uint256 nonce_) public OnlyAuthorized {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();

        if (nonce_ <= $.nonce) revert InvalidNonce();

        $.nonce = nonce_;

        emit updateNonce(nonce_);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function _isValidLightSyncSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        LightSyncSignature memory lightSyncSignature_,
        uint256 nonce_,
        bytes memory signerUpdates_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature(
                $_,
                _getAddSignerHash(lightSyncSignature_.update, nonce_),
                lightSyncSignature_.signatures,
                signerUpdates_
            )
        ) {
            revert LightSyncUpdateValidationFailed(lightSyncSignature_);
        }
    }

    function _isValidLightSyncSignature(
        MultiSignerLib.MultiSignerStorage storage $_,
        LightSyncSignature memory lightSyncSignature_,
        uint256 nonce_
    )
        internal
        view
    {
        if (
            !MultiSignerSignatureLib.isValidSignature(
                $_, _getAddSignerHash(lightSyncSignature_.update, nonce_), lightSyncSignature_.signatures
            )
        ) {
            revert LightSyncUpdateValidationFailed(lightSyncSignature_);
        }
    }

    function _validateAndProcessLightSyncSignaturesMemory(LightSyncSignature[] memory lightSyncSigs_)
        internal
        view
        returns (bytes memory signerUpdates)
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;
        uint256 numUpdates = lightSyncSigs_.length;

        signerUpdates = new bytes(MultiSignerSignatureLib.SIGNER_SIZE * numUpdates);

        uint256 signerAddedBitMap;

        for (uint256 i; i < numUpdates; i++) {
            _isValidLightSyncSignature($, lightSyncSigs_[i], nonce++, signerUpdates);

            signerAddedBitMap = _addSignerMemory(
                i, lightSyncSigs_[i].update.index, lightSyncSigs_[i].update.signer, signerAddedBitMap, signerUpdates
            );
        }
    }

    function _validateAndProcessLightSyncSignatures(LightSyncSignature[] memory lightSyncSigs_) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint256 nonce = $.nonce;
        uint256 numUpdates = lightSyncSigs_.length;
        for (uint256 i; i < numUpdates; i++) {
            _isValidLightSyncSignature($, lightSyncSigs_[i], nonce++);
            _addSigner(lightSyncSigs_[i].update);
        }
        $.nonce = nonce;
        emit updateNonce(nonce);
    }

    function _addSigner(SignerSetUpdate memory update_) internal {
        _addSigner(update_.signer, update_.index);
    }

    function _addSignerMemory(
        uint256 insertIndex_,
        uint8 signerIndex_,
        bytes memory signer_,
        uint256 signerAddedBitMap_,
        bytes memory addedSigners_
    )
        internal
        pure
        returns (uint256)
    {
        MultiSignerLib.validateSigner(signer_);

        uint256 bitMask = 1 << signerIndex_;
        if (signerAddedBitMap_ & bitMask != 0) {
            revert SignerAlreadyPresent(signerIndex_);
        }
        signerAddedBitMap_ = signerAddedBitMap_ | bitMask;

        uint8 signerType;
        if (signer_.length == MultiSignerLib.EOA_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.EOA_SIGNER_TYPE;
        } else if (signer_.length == MultiSignerLib.PASSKEY_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.PASSKEY_SIGNER_TYPE;
        }

        assembly {
            let destPtr := add(add(addedSigners_, 32), mul(insertIndex_, 66))
            mstore8(destPtr, signerIndex_)
            mstore8(add(destPtr, 1), signerType)

            let dataPtr := add(signer_, 32)

            switch signerType
            case 1 { mstore(add(destPtr, 2), mload(dataPtr)) }
            case 2 {
                mstore(add(destPtr, 2), mload(dataPtr)) // Copy first 32 bytes
                mstore(add(destPtr, 34), mload(add(dataPtr, 32))) // Copy second 32 bytes
            }
        }

        return signerAddedBitMap_;
    }

    function _getAddSignerHash(SignerSetUpdate memory update_, uint256 nonce_) internal view returns (bytes32) {
        return keccak256(abi.encode(nonce_, address(this), update_));
    }
}
