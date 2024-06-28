// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { MultiSignerLib } from "../library/MultiSignerLib.sol";

/// @notice Storage layout used by this contract.
/// @dev Can allow upto 256 signers.
/// @custom:storage-location erc7201:splits.storage.MultiSigner
struct MultiSignerStorage {
    /// @dev Number of unique signatures required to validate a message signed by this contract.
    uint8 threshold;
    /// @dev number of signers
    uint8 signerCount;
    /// @dev signer bytes;
    mapping(uint8 => bytes) signers;
    /// @dev tracks if provided bytes is signer.
    mapping(bytes => bool) isSigner;
}

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
    bytes32 private constant MUTLI_SIGNER_STORAGE_LOCATION =
        0xc6b44c835744ff7e5272b762d148484b103b956d9f16ac625b855244e8132a00;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when threshold is greater than number of signers or when zero.
    error InvalidThreshold();

    /// @notice Thrown when number of signers is more than 256.
    error InvalidNumberOfSigners();

    /**
     * @notice Thrown when trying to overwrite signer at a given index.
     * @param index Index already has a signer.
     */
    error SignerPresentAtIndex(uint8 index);

    /**
     * @notice Thrown when trying to add the same signer.
     * @param signer duplicate signer.
     */
    error SignerAlreadyAdded(bytes signer);

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
        authorizeUpdate();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                            PUBLIC VIEW FUNCTIONS                           */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns if the passed in _signer is registered.
    function isSigner(bytes calldata _signer) public view virtual returns (bool) {
        return getMultiSignerStorage().isSigner[_signer];
    }

    /// @notice Returns the owner bytes at the given `index`.
    function signerAtIndex(uint8 index) public view virtual returns (bytes memory) {
        return getMultiSignerStorage().signers[index];
    }

    /// @notice Returns the current number of signers
    function signerCount() public view virtual returns (uint256) {
        return getMultiSignerStorage().signerCount;
    }

    /// @notice Returns the threshold
    function threshold() public view virtual returns (uint8) {
        return getMultiSignerStorage().threshold;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds a `signer` at the `index`.
     *
     * @dev Reverts if `signer` is already registered.
     * @dev Reverts if `index` already has a signer.
     *
     * @param _signer The owner raw bytes to register.
     */
    function addSigner(bytes calldata _signer, uint8 _index) public OnlyAuthorized {
        MultiSignerStorage storage $ = getMultiSignerStorage();

        if ($.isSigner[_signer]) revert SignerAlreadyAdded(_signer);
        if ($.signers[_index].length > 0) revert SignerPresentAtIndex(_index);

        MultiSignerLib.validateSigner(_signer);

        $.isSigner[_signer] = true;
        $.signers[_index] = _signer;
        $.signerCount += 1;

        emit AddSigner(_index, _signer);
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @param _index The index of the signer to be removed.
     */
    function removeSigner(uint8 _index) public OnlyAuthorized {
        MultiSignerStorage storage $ = getMultiSignerStorage();

        uint256 signerCount_ = $.signerCount;

        if (signerCount_ == $.threshold) revert InvalidThreshold();

        bytes memory signer = $.signers[_index];

        delete $.isSigner[signer];
        delete $.signers[_index];
        $.signerCount -= 1;

        emit RemoveSigner(_index, signer);
    }

    /**
     * @notice Updates threshold of the signer set.
     * @dev Reverts if 'threshold' is greater than owner count.
     * @dev Reverts if 'threshold' is 0.
     */
    function updateThreshold(uint8 _threshold) public OnlyAuthorized {
        if (_threshold == 0) revert InvalidThreshold();
        MultiSignerStorage storage $ = getMultiSignerStorage();
        if ($.signerCount < _threshold) revert InvalidThreshold();
        $.threshold = _threshold;

        emit UpdateThreshold(_threshold);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initialize the signers of this contract.
     * @dev Intended to be called when contract is first deployed and never again.
     * @dev Reverts if a provided owner is neither 64 bytes long (for public key) nor a valid address.
     * @dev Reverts if 'threshold' is less than number of signers.
     * @dev Reverts if 'threshold' is 0.
     * @dev Reverts if number of signers is more than 256.
     * @param _signers The initial set of signers.
     * @param _threshold The number of signers needed for approval.
     */
    function initializeSigners(bytes[] calldata _signers, uint8 _threshold) internal virtual {
        if (_signers.length > 255 || _signers.length == 0) revert InvalidNumberOfSigners();

        uint8 numberOfSigners = uint8(_signers.length);

        if (numberOfSigners < _threshold || _threshold < 1) revert InvalidThreshold();

        MultiSignerStorage storage $ = getMultiSignerStorage();

        bytes memory signer;

        for (uint8 i; i < numberOfSigners; i++) {
            signer = _signers[i];

            MultiSignerLib.validateSigner(signer);

            $.isSigner[signer] = true;
            $.signers[i] = signer;

            emit AddSigner(i, signer);
        }

        $.signerCount = numberOfSigners;
        $.threshold = _threshold;
    }

    /// @notice Helper function to get a storage reference to the `MultiSignerStorage` struct.
    function getMultiSignerStorage() internal pure returns (MultiSignerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_SIGNER_STORAGE_LOCATION
        }
    }

    function authorizeUpdate() internal virtual;
}
