// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSigner } from "../signers/MultiSigner.sol";
import { Signer } from "../signers/Signer.sol";

/**
 * @title Multi Signer Auth
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Auth contract allowing multiple signers, each identified as `Signer` with a specified threshold.
 * @dev Based on Coinbase's Smart Wallet Multi Ownable (https://github.com/coinbase/smart-wallet)
 */
abstract contract MultiSignerAuth {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `MultiSignerStorage` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.multiSignerAuth")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 private constant _MUTLI_SIGNER_AUTH_STORAGE_LOCATION =
        0x3e5431599761dc1a6f375d94085bdcd73bc8fa7c6b3d455d31679f3080214700;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCT                                   */
    /* -------------------------------------------------------------------------- */

    /// @custom:storage-location erc7201:splits.storage.multiSignerAuth
    struct MultiSignerAuthStorage {
        MultiSigner signers;
    }

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
    event AddSigner(uint256 indexed index, Signer signer);

    /**
     * @notice Emitted when a signer is removed.
     * @param index The index of the signer removed.
     * @param signer The signer removed.
     */
    event RemoveSigner(uint256 indexed index, Signer signer);

    /**
     * @notice Emitted when threshold is updated.
     * @param threshold The new threshold for the signer set.
     */
    event UpdateThreshold(uint8 threshold);

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyAuthorized() {
        _authorize();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                            PUBLIC VIEW FUNCTIONS                           */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns the owner bytes at the given `index`.
    function getSigner(uint8 index_) public view virtual returns (Signer memory) {
        return _getMultiSignerAuthStorage().signers.getSigner(index_);
    }

    /// @notice Returns the current number of signers
    function getSignerCount() public view virtual returns (uint8) {
        return _getMultiSignerAuthStorage().signers.getSignerCount();
    }

    /// @notice Returns the threshold
    function getThreshold() public view virtual returns (uint8) {
        return _getMultiSignerAuthStorage().signers.getThreshold();
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds a `signer` at the `index`.
     *
     * @dev Reverts if Signer is neither EOA or Passkey.
     *
     * @param signer_ The owner raw bytes to register.
     * @param index_ The index to register the signer.
     */
    function addSigner(Signer calldata signer_, uint8 index_) external onlyAuthorized {
        MultiSignerAuthStorage storage $ = _getMultiSignerAuthStorage();

        if (!$.signers.getSigner(index_).isEmptyMem()) revert SignerAlreadyPresent(index_);

        $.signers.addSigner(signer_, index_);
        $.signers.updateSignerCount($.signers.getSignerCount() + 1);

        emit AddSigner(index_, signer_);
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @dev Reverts if 'threshold' is equal to signer count.
     * @dev Reverts if signer is empty at `index`.
     *
     * @param index_ The index of the signer to be removed.
     */
    function removeSigner(uint8 index_) external onlyAuthorized {
        MultiSignerAuthStorage storage $ = _getMultiSignerAuthStorage();

        uint8 signerCount = $.signers.getSignerCount();

        if (signerCount == $.signers.getThreshold()) revert InvalidThreshold();

        Signer memory signer = $.signers.getSigner(index_);

        if (signer.isEmptyMem()) revert SignerNotPresent(index_);

        $.signers.removeSigner(index_);
        $.signers.updateSignerCount(signerCount - 1);

        emit RemoveSigner(index_, signer);
    }

    /**
     * @notice Updates threshold of the signer set.
     *
     * @dev Reverts if 'threshold' is greater than signer count.
     * @dev Reverts if 'threshold' is 0.
     *
     * @param threshold_ The new signer set threshold.
     */
    function updateThreshold(uint8 threshold_) external onlyAuthorized {
        if (threshold_ == 0) revert InvalidThreshold();

        MultiSignerAuthStorage storage $ = _getMultiSignerAuthStorage();
        if ($.signers.getSignerCount() < threshold_) revert InvalidThreshold();

        $.signers.updateThreshold(threshold_);

        emit UpdateThreshold(threshold_);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function _authorize() internal virtual;

    /// @notice Helper function to get storage reference to the `MultiSignerStorage` struct.
    function _getMultiSignerAuthStorage() internal pure returns (MultiSignerAuthStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _MUTLI_SIGNER_AUTH_STORAGE_LOCATION
        }
    }

    /**
     * @notice Initialize the signers of this contract.
     *
     * @dev Intended to be called when contract is first deployed and never again.
     * @dev Reverts if signer is neither an EOA or a passkey.
     * @dev Reverts if 'threshold' is less than number of signers.
     * @dev Reverts if 'threshold' is 0.
     * @dev Reverts if number of signers is more than 256.
     *
     * @param signers_ The initial set of signers.
     * @param threshold_ The number of signers needed for approval.
     */
    function _initializeSigners(Signer[] calldata signers_, uint8 threshold_) internal virtual {
        if (signers_.length > type(uint8).max || signers_.length == 0) revert InvalidNumberOfSigners();

        uint8 numSigners = uint8(signers_.length);

        if (numSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        MultiSignerAuthStorage storage $ = _getMultiSignerAuthStorage();

        for (uint8 i; i < numSigners; i++) {
            $.signers.addSigner(signers_[i], i);

            emit AddSigner(i, signers_[i]);
        }

        $.signers.updateSignerCount(numSigners);
        $.signers.updateThreshold(threshold_);

        emit UpdateThreshold(threshold_);
    }
}
