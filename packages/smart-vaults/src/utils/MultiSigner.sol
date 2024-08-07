// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { WebAuthn } from "@web-authn/WebAuthn.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title Multi Signer
 * @author Splits
 * @notice Auth contract allowing multiple signers, each identified as bytes with a specified threshold.
 * @dev Base on Coinbase's Smart Wallet Multi Ownable (https://github.com/coinbase/smart-wallet)
 */
abstract contract MultiSigner {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `MultiSignerStorage` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.MultiSigner")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 private constant _MUTLI_SIGNER_STORAGE_LOCATION =
        0xc6b44c835744ff7e5272b762d148484b103b956d9f16ac625b855244e8132a00;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when threshold is greater than number of signers or when zero.
    error InvalidThreshold();

    /// @notice Thrown when number of signers is more than 256.
    error InvalidNumberOfSigners();

    /**
     * @notice Thrown when trying to remove an empty signer.
     * @param index Index of the empty signer.
     */
    error SignerNotPresent(uint8 index);

    /**
     * @notice Thrown when trying to replace an existing signer.
     * @param index Index of the existing signer.
     */
    error SignerAlreadyPresent(uint8 index);

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Emitted when a new signer is registered.
     * @param index The index of the signer added.
     * @param signer The signer added.
     */
    event AddSigner(uint256 indexed index, bytes signer);

    /**
     * @notice Emitted when a signer is removed.
     * @param index The index of the signer removed.
     * @param signer The signer removed.
     */
    event RemoveSigner(uint256 indexed index, bytes signer);

    /**
     * @notice Emitted when threshold is updated.
     * @param threshold The new threshold for the signer set.
     */
    event UpdateThreshold(uint8 threshold);

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier OnlyAuthorized() {
        _authorize();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                            PUBLIC VIEW FUNCTIONS                           */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns the owner bytes at the given `index`.
    function getSignerAtIndex(uint8 index_) public view virtual returns (bytes memory) {
        return _getMultiSignerStorage().signers[index_];
    }

    /// @notice Returns the current number of signers
    function getSignerCount() public view virtual returns (uint256) {
        return _getMultiSignerStorage().signerCount;
    }

    /// @notice Returns the threshold
    function getThreshold() public view virtual returns (uint8) {
        return _getMultiSignerStorage().threshold;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds a `signer` at the `index`.
     *
     * @param signer_ The owner raw bytes to register.
     * @param index_ The index to register the signer.
     */
    function addSigner(bytes calldata signer_, uint8 index_) public OnlyAuthorized {
        _addSigner(signer_, index_);
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @dev Reverts if 'threshold' is equal to signer count.
     *
     * @param index_ The index of the signer to be removed.
     */
    function removeSigner(uint8 index_) public OnlyAuthorized {
        _removeSigner(index_);
    }

    /**
     * @notice Updates threshold of the signer set.
     *
     * @dev Reverts if 'threshold' is greater than signer count.
     * @dev Reverts if 'threshold' is 0.
     *
     * @param threshold_ The new signer set threshold.
     */
    function updateThreshold(uint8 threshold_) public OnlyAuthorized {
        _updateThreshold(threshold_);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function _authorize() internal virtual;

    /// @notice Helper function to get storage reference to the `MultiSignerStorage` struct.
    function _getMultiSignerStorage() internal pure returns (MultiSignerLib.MultiSignerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _MUTLI_SIGNER_STORAGE_LOCATION
        }
    }

    /**
     * @notice Initialize the signers of this contract.
     * @dev Intended to be called when contract is first deployed and never again.
     * @dev Reverts if a provided owner is neither 64 bytes long (for public key) nor a valid address.
     * @dev Reverts if 'threshold' is less than number of signers.
     * @dev Reverts if 'threshold' is 0.
     * @dev Reverts if number of signers is more than 256.
     * @param signers_ The initial set of signers.
     * @param threshold_ The number of signers needed for approval.
     */
    function _initializeSigners(bytes[] calldata signers_, uint8 threshold_) internal virtual {
        if (signers_.length > 255 || signers_.length == 0) revert InvalidNumberOfSigners();

        uint8 numSigners = uint8(signers_.length);

        if (numSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();

        bytes memory signer;

        for (uint8 i; i < numSigners; i++) {
            signer = signers_[i];

            MultiSignerLib.validateSigner(signer);

            $.signers[i] = signer;

            emit AddSigner(i, signer);
        }

        $.signerCount = numSigners;

        $.threshold = threshold_;
        emit UpdateThreshold(threshold_);
    }

    function _addSigner(bytes memory signer_, uint8 index_) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();

        MultiSignerLib.validateSigner(signer_);

        if ($.signers[index_].length != 0) revert SignerAlreadyPresent(index_);

        $.signerCount += 1;
        $.signers[index_] = signer_;

        emit AddSigner(index_, signer_);
    }

    function _removeSigner(uint8 index_) internal {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();

        uint256 signerCount_ = $.signerCount;

        if (signerCount_ == $.threshold) revert InvalidThreshold();

        bytes memory signer = $.signers[index_];
        if (signer.length == 0) revert SignerNotPresent(index_);

        delete $.signers[index_];
        $.signerCount -= 1;

        emit RemoveSigner(index_, signer);
    }

    function _updateThreshold(uint8 threshold_) internal {
        if (threshold_ == 0) revert InvalidThreshold();

        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        if ($.signerCount < threshold_) revert InvalidThreshold();

        $.threshold = threshold_;
        emit UpdateThreshold(threshold_);
    }
}
