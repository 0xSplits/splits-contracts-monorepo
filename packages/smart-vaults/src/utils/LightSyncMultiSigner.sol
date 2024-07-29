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
        /**
         * AddSigner: abi.encode(uint8 index, uint8 signerType, bytes signer)
         */
        bytes data;
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
        signerUpdates = new bytes(66 * numUpdates);

        uint256 memorySignerSet;

        for (uint256 i; i < numUpdates; i++) {
            _validateSignerSetUpdateMemory({
                $_: $,
                signerSetUpdate_: signerSetUpdates_[i],
                signerUpdates_: signerUpdates,
                nonce_: nonce++
            });
            memorySignerSet = _processSignerSetUpdateMemory(i, signerSetUpdates_[i], memorySignerSet, signerUpdates);
        }
    }

    /// @notice reverts if validation fails
    function _validateSignerSetUpdateMemory(
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

    function _processSignerSetUpdateMemory(
        uint256 insertIndex_,
        SignerSetUpdate memory signerSetUpdate_,
        uint256 memorySignerSet_,
        bytes memory signerUpdates_
    )
        internal
        view
        returns (uint256)
    {
        (bytes memory signer, uint8 index) = abi.decode(signerSetUpdate_.data, (bytes, uint8));
        MultiSignerLib.validateSigner(signer);

        uint256 bitMask = 1 << index;
        if (memorySignerSet_ & bitMask != 0) {
            revert SignerAlreadyPresent(index);
        }
        memorySignerSet_ = memorySignerSet_ | bitMask;

        uint8 signerType;
        if (signer.length == MultiSignerLib.EOA_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.EOA_SIGNER_TYPE;
        } else if (signer.length == MultiSignerLib.PASSKEY_SIGNER_SIZE) {
            signerType = MultiSignerSignatureLib.PASSKEY_SIGNER_TYPE;
        }

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

        return memorySignerSet_;
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
