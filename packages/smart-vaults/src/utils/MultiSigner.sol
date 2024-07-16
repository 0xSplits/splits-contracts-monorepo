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
    bytes32 private constant MUTLI_SIGNER_STORAGE_LOCATION =
        0xc6b44c835744ff7e5272b762d148484b103b956d9f16ac625b855244e8132a00;

    bytes32 private constant SIGNER_REMOVED = 0xb04ab4afa2f1583231336fc5be76c590578027387608a6a8dc2e65a46dbe66d3;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Storage layout used by this contract.
    /// @dev Can allow upto 256 signers.
    /// @custom:storage-location erc7201:splits.storage.MultiSigner
    struct MultiSignerStorage {
        uint256 nonce;
        /// @dev Number of unique signatures required to validate a message signed by this contract.
        uint8 threshold;
        /// @dev number of signers
        uint8 signerCount;
        /// @dev signer bytes;
        mapping(uint8 => bytes) signers;
    }

    /**
     * @notice A wrapper struct used for signature validation so that callers
     *         can identify the signer that signed.
     */
    struct SignatureWrapper {
        /// @dev The index of the signer that signed, see `MultiSigner.signerAtIndex`
        uint8 signerIndex;
        /**
         * @dev If `MultiSigner.signerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
         *      If `MultiSigner.signerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
         */
        bytes signatureData;
    }

    enum RootSignatureType {
        userOp,
        stateSync
    }

    struct RootSignature {
        RootSignatureType sigType;
        bytes signature;
    }

    enum UserOpSignatureType {
        normal,
        multiChain
    }

    struct UserOpSignature {
        UserOpSignatureType sigType;
        bytes signature;
    }

    struct NormalSignature {
        SignatureWrapper[] signature;
    }

    struct MultiChainSignature {
        bytes32 merkleTreeRoot;
        bytes32[] merkleProofs;
        bytes normalSignature;
    }

    enum SignerUpdateType {
        addSigner,
        removeSigner,
        updateThreshold
    }

    struct SignerUpdateParam {
        SignerUpdateType updateType;
        bytes data;
    }

    struct SignerUpdate {
        SignerUpdateParam[] updateParams;
        bytes normalSignature;
    }

    struct StateSyncSignature {
        SignerUpdate[] updates;
        bytes userOpSignature;
    }

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

    /// @notice Thrown when number of signatures is less than threshold.
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);

    /// @notice Thrown when duplicate signer is encountered.
    error DuplicateSigner(uint8 signerIndex);

    error SignerUpdateValidationFailed(SignerUpdate);

    error InvalidSignerUpdateParam(SignerUpdateParam);

    error InvalidSigner(uint8 signerIndex);

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

    /// @notice Returns the owner bytes at the given `index`.
    function signerAtIndex(uint8 index) public view virtual returns (bytes memory) {
        return getMultiSignerStorage().signers[index];
    }

    /// @notice Returns the current number of signers
    function signerCount() public view virtual returns (uint256) {
        return getMultiSignerStorage().signerCount;
    }

    /// @notice Returns the threshold
    function getThreshold() public view virtual returns (uint8) {
        return getMultiSignerStorage().threshold;
    }

    /// @notice Returns the nonce for the signer set
    function getNonce() public view virtual returns (uint256) {
        return getMultiSignerStorage().nonce;
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
        _addSigner(_signer, _index);
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @param _index The index of the signer to be removed.
     */
    function removeSigner(uint8 _index) public OnlyAuthorized {
        _removeSigner(_index);
    }

    /**
     * @notice Updates threshold of the signer set.
     * @dev Reverts if 'threshold' is greater than owner count.
     * @dev Reverts if 'threshold' is 0.
     */
    function updateThreshold(uint8 _threshold) public OnlyAuthorized {
        _updateThreshold(_threshold);
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

    /**
     * @notice validates if the given hash was signed by the signers.
     */
    function validateNormalSignature(bytes32 _hash, bytes memory _signature) internal view returns (bool) {
        NormalSignature memory signature = abi.decode(_signature, (NormalSignature));
        SignatureWrapper[] memory sigWrappers = signature.signature;
        uint256 numberOfSignatures = sigWrappers.length;

        uint8 threshold_ = getThreshold();
        if (numberOfSignatures < threshold_) revert MissingSignatures(numberOfSignatures, threshold_);

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        for (uint256 i; i < numberOfSignatures; i++) {
            signerIndex = sigWrappers[i].signerIndex;
            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            if (MultiSignerLib.isValidSignature(_hash, signerAtIndex(signerIndex), sigWrappers[i].signatureData)) {
                alreadySigned |= mask;
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice validates if the given hash was signed by the signers.
     */
    function validateNormalSignature(
        bytes32 _hash,
        bytes memory _signature,
        bytes[256] memory _signers,
        uint8 _threshold
    )
        internal
        view
        returns (bool)
    {
        NormalSignature memory signature = abi.decode(_signature, (NormalSignature));
        SignatureWrapper[] memory sigWrappers = signature.signature;
        uint256 numberOfSignatures = sigWrappers.length;

        if (numberOfSignatures < _threshold) revert MissingSignatures(numberOfSignatures, _threshold);

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bytes memory signer;
        for (uint256 i; i < numberOfSignatures; i++) {
            signerIndex = sigWrappers[i].signerIndex;
            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            signer = _signers[signerIndex];
            if (signer.length == 0) {
                signer = signerAtIndex(signerIndex);
            } else if (bytes32(signer) == SIGNER_REMOVED) {
                revert InvalidSigner(signerIndex);
            }

            if (MultiSignerLib.isValidSignature(_hash, signer, sigWrappers[i].signatureData)) {
                alreadySigned |= mask;
            } else {
                return false;
            }
        }
        return true;
    }

    /**
     * @notice validates if the given hash was signed by the signer.
     */
    function validateSignature(
        bytes32 _hash,
        uint8 _signerIndex,
        bytes memory _signature
    )
        internal
        view
        returns (bool)
    {
        return MultiSignerLib.isValidSignature(_hash, signerAtIndex(_signerIndex), _signature);
    }

    function processSignerUpdates(SignerUpdate[] memory _signerUpdates) internal {
        uint256 noOfUpdates = _signerUpdates.length;
        for (uint256 i; i < noOfUpdates; i++) {
            validateSignerUpdate(_signerUpdates[i]);
            processsSignerUpdate(_signerUpdates[i]);
        }
    }

    /// @notice reverts if validation fails
    function validateSignerUpdate(SignerUpdate memory _signerUpdate) internal view {
        if (
            !validateNormalSignature(
                getSignerUpdateHash(_signerUpdate, getMultiSignerStorage().nonce), _signerUpdate.normalSignature
            )
        ) revert SignerUpdateValidationFailed(_signerUpdate);
    }

    function processsSignerUpdate(SignerUpdate memory _signerUpdate) internal {
        SignerUpdateParam[] memory updateParams = _signerUpdate.updateParams;
        uint256 noOfUpdates = updateParams.length;
        for (uint256 i; i < noOfUpdates; i++) {
            processsSignerUpdateParam(updateParams[i]);
        }
        getMultiSignerStorage().nonce += 1;
    }

    function processsSignerUpdatesMemory(SignerUpdate[] memory _signerUpdates)
        internal
        view
        returns (bytes[256] memory signers, uint8 threshold)
    {
        uint256 nonce = getMultiSignerStorage().nonce;
        uint256 noOfUpdates = _signerUpdates.length;
        threshold = getThreshold();
        for (uint256 i; i < noOfUpdates; i++) {
            validateSignerUpdateMemory(_signerUpdates[i], signers, threshold, nonce++);
            (signers, threshold) = processsSignerUpdateMemory(_signerUpdates[i], signers, threshold);
        }
    }

    /// @notice reverts if validation fails
    function validateSignerUpdateMemory(
        SignerUpdate memory _signerUpdate,
        bytes[256] memory _signers,
        uint8 _threshold,
        uint256 _nonce
    )
        internal
        view
    {
        if (
            !validateNormalSignature(
                getSignerUpdateHash(_signerUpdate, _nonce), _signerUpdate.normalSignature, _signers, _threshold
            )
        ) {
            revert SignerUpdateValidationFailed(_signerUpdate);
        }
    }

    function processsSignerUpdateMemory(
        SignerUpdate memory _signerUpdate,
        bytes[256] memory _signers,
        uint8 _threshold
    )
        internal
        view
        returns (bytes[256] memory, uint8)
    {
        SignerUpdateParam[] memory updateParams = _signerUpdate.updateParams;
        uint256 noOfUpdates = updateParams.length;

        for (uint256 i; i < noOfUpdates; i++) {
            SignerUpdateParam memory _signerUpdateParam = updateParams[i];
            if (_signerUpdateParam.updateType == SignerUpdateType.addSigner) {
                (bytes memory signer, uint8 index) = abi.decode(_signerUpdateParam.data, (bytes, uint8));
                MultiSignerLib.validateSigner(signer);
                _signers[index] = signer;
            } else if (_signerUpdateParam.updateType == SignerUpdateType.removeSigner) {
                uint8 index = abi.decode(_signerUpdateParam.data, (uint8));
                _signers[index] = bytes.concat(SIGNER_REMOVED);
            } else if (_signerUpdateParam.updateType == SignerUpdateType.updateThreshold) {
                _threshold = abi.decode(_signerUpdateParam.data, (uint8));
            } else {
                revert InvalidSignerUpdateParam(_signerUpdateParam);
            }
        }

        return (_signers, _threshold);
    }

    function processsSignerUpdateParam(SignerUpdateParam memory _signerUpdateParam) internal {
        if (_signerUpdateParam.updateType == SignerUpdateType.addSigner) {
            (bytes memory signer, uint8 index) = abi.decode(_signerUpdateParam.data, (bytes, uint8));
            _addSigner(signer, index);
        } else if (_signerUpdateParam.updateType == SignerUpdateType.removeSigner) {
            uint8 index = abi.decode(_signerUpdateParam.data, (uint8));
            _removeSigner(index);
        } else if (_signerUpdateParam.updateType == SignerUpdateType.updateThreshold) {
            uint8 threshold_ = abi.decode(_signerUpdateParam.data, (uint8));
            _updateThreshold(threshold_);
        } else {
            revert InvalidSignerUpdateParam(_signerUpdateParam);
        }
    }

    function getSignerUpdateHash(SignerUpdate memory _signerUpdate, uint256 _nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(_nonce, address(this), _signerUpdate.updateParams));
    }

    function authorizeUpdate() internal virtual;

    function _addSigner(bytes memory _signer, uint8 _index) internal {
        MultiSignerStorage storage $ = getMultiSignerStorage();

        MultiSignerLib.validateSigner(_signer);

        if ($.signers[_index].length == 0) $.signerCount += 1;
        $.signers[_index] = _signer;

        emit AddSigner(_index, _signer);
    }

    function _removeSigner(uint8 _index) internal {
        MultiSignerStorage storage $ = getMultiSignerStorage();

        uint256 signerCount_ = $.signerCount;

        if (signerCount_ == $.threshold) revert InvalidThreshold();

        bytes memory signer = $.signers[_index];

        delete $.signers[_index];
        $.signerCount -= 1;

        emit RemoveSigner(_index, signer);
    }

    function _updateThreshold(uint8 _threshold) internal {
        if (_threshold == 0) revert InvalidThreshold();
        MultiSignerStorage storage $ = getMultiSignerStorage();
        if ($.signerCount < _threshold) revert InvalidThreshold();
        $.threshold = _threshold;

        emit UpdateThreshold(_threshold);
    }
}
