// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:splits.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev signer threshold required to validate a message signed by this contract.
    uint8 threshold;
    /// @dev Tracks the index of the next owner to add.
    uint256 nextOwnerIndex;
    /// @dev Tracks number of owners that have been removed.
    uint256 removedOwnersCount;
    /**
     * @dev Maps index to owner bytes, used to idenfitied owners via a uint256 index.
     *
     *      Some uses—-such as signature validation for secp256r1 public key owners—-
     *      requires the caller to assert the public key of the caller. To economize calldata,
     *      we allow an index to identify an owner, so that the full owner bytes do
     *      not need to be passed.
     *
     *      The `owner` bytes should either be
     *         - An ABI encoded Ethereum address
     *         - An ABI encoded public key
     */
    mapping(uint256 index => bytes owner) ownerAtIndex;
    /// @dev Mapping of bytes to booleans indicating whether or not bytes_ is an owner of this contract.
    mapping(bytes bytes_ => bool isOwner_) isOwner;
}

/**
 * @title Multi Ownable
 * @author Splits
 * @notice Auth contract allowing multiple owners, each identified as bytes with a specified threshold.
 * @dev Base on Coinbase's Smart Wallet Multi Ownable (https://github.com/coinbase/smart-wallet)
 */
abstract contract MultiOwnable {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `MultiOwnableStorage` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
        0x58a657953eb022c381f0b3af304f268f9fc6d2a1e5a6ac911bd1f13ed2165900;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Thrown when trying to add an already registered owner.
     * @param owner The owner bytes.
     */
    error AlreadyOwner(bytes owner);

    /**
     * @notice Thrown when trying to remove an owner from an index that is empty.
     * @param index The targeted index for removal.
     */
    error NoOwnerAtIndex(uint256 index);

    /**
     * @notice Thrown when `owner` argument does not match owner found at index.
     * @param index         The index of the owner to be removed.
     * @param expectedOwner The owner passed in the remove call.
     * @param actualOwner   The actual owner at `index`.
     */
    error WrongOwnerAtIndex(uint256 index, bytes expectedOwner, bytes actualOwner);

    /**
     * @notice Thrown when a provided owner is neither 64 bytes long (for public key)
     *         nor a ABI encoded address.
     * @param owner The invalid owner.
     */
    error InvalidOwnerBytesLength(bytes owner);

    /**
     * @notice Thrown if a provided owner is 32 bytes long but does not fit in an `address` type.
     * @param owner The invalid owner.
     */
    error InvalidEthereumAddressOwner(bytes owner);

    /// @notice Thrown when removeOwnerAtIndex is called and there is only one current owner.
    error LastOwner();

    /// @notice Thrown when threshold is greater than number of owners.
    error InvalidThreshold();

    /**
     * @notice Thrown when removeLastOwner is called and there is more than one current owner.
     * @param ownersRemaining The number of current owners.
     */
    error NotLastOwner(uint256 ownersRemaining);

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Emitted when a new owner is registered.
     * @param index The owner index of the owner added.
     * @param owner The owner added.
     */
    event AddOwner(uint256 indexed index, bytes owner);

    /**
     * @notice Emitted when an owner is removed.
     * @param index The owner index of the owner removed.
     * @param owner The owner removed.
     */
    event RemoveOwner(uint256 indexed index, bytes owner);

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

    /// @notice Checks if the given `account` address is registered as owner.
    function isOwnerAddress(address account) public view virtual returns (bool) {
        return getMultiOwnableStorage().isOwner[abi.encode(account)];
    }

    /// @notice Checks if the given `x`, `y` public key is registered as owner.
    function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return getMultiOwnableStorage().isOwner[abi.encode(x, y)];
    }

    /// @notice Checks if the given `account` bytes is registered as owner.
    function isOwnerBytes(bytes memory account) public view virtual returns (bool) {
        return getMultiOwnableStorage().isOwner[account];
    }

    /// @notice Returns the owner bytes at the given `index`.
    function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return getMultiOwnableStorage().ownerAtIndex[index];
    }

    /// @notice Returns the next index that will be used to add a new owner.
    function nextOwnerIndex() public view virtual returns (uint256) {
        return getMultiOwnableStorage().nextOwnerIndex;
    }

    /// @notice Returns the current number of owners
    function ownerCount() public view virtual returns (uint256) {
        MultiOwnableStorage storage $ = getMultiOwnableStorage();
        return $.nextOwnerIndex - $.removedOwnersCount;
    }

    /// @notice Returns the threshold
    function threshold() public view virtual returns (uint8) {
        return getMultiOwnableStorage().threshold;
    }

    /// @notice Tracks the number of owners removed
    function removedOwnersCount() public view virtual returns (uint256) {
        return getMultiOwnableStorage().removedOwnersCount;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds an owner at the next owner index.
     *
     * @dev Reverts if `owner` is already registered as an owner.
     *
     * @param _owner The owner raw bytes to register.
     */
    function addOwner(bytes calldata _owner) public OnlyAuthorized {
        MultiOwnableStorage storage $ = getMultiOwnableStorage();

        uint256 index_ = $.nextOwnerIndex++;
        if (isOwnerBytes(_owner)) revert AlreadyOwner(_owner);

        $.isOwner[_owner] = true;
        $.ownerAtIndex[index_] = _owner;

        emit AddOwner(index_, _owner);
    }

    /**
     * @notice Removes owner at the given `index`.
     *
     * @dev Reverts if the owner is not registered at `index`.
     * @dev Reverts if `owner` does not match bytes found at `index`.
     *
     * @param _index The index of the owner to be removed.
     * @param _owner The ABI encoded bytes of the owner to be removed.
     */
    function removeOwner(uint256 _index, bytes calldata _owner) public OnlyAuthorized {
        MultiOwnableStorage storage $ = getMultiOwnableStorage();

        uint256 ownerCount_ = $.nextOwnerIndex - $.removedOwnersCount;

        if (ownerCount_ == $.threshold) revert InvalidThreshold();
        if (ownerCount_ == 1) revert LastOwner();

        bytes memory owner_ = $.ownerAtIndex[_index];
        if (owner_.length == 0) revert NoOwnerAtIndex(_index);
        if (keccak256(owner_) != keccak256(_owner)) {
            revert WrongOwnerAtIndex({ index: _index, expectedOwner: _owner, actualOwner: owner_ });
        }

        delete $.isOwner[_owner];
        delete $.ownerAtIndex[_index];
        $.removedOwnersCount++;

        emit RemoveOwner(_index, _owner);
    }

    /**
     * @notice Updates threshold of the owner set.
     * @dev Reverts if 'threshold' is greater than owner count.
     * @dev Reverts if 'threshold' is less than 1.
     */
    function updateThreshold(uint8 _threshold) public OnlyAuthorized {
        if (_threshold < 1) revert InvalidThreshold();
        MultiOwnableStorage storage $ = getMultiOwnableStorage();
        if (($.nextOwnerIndex - $.removedOwnersCount) < _threshold) revert InvalidThreshold();
        $.threshold = _threshold;

        emit UpdateThreshold(_threshold);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initialize the owners of this contract.
     * @dev Intended to be called contract is first deployed and never again.
     * @dev Reverts if a provided owner is neither 64 bytes long (for public key) nor a valid address.
     * @dev Reverts if 'threshold' is less than number of owners.
     * @dev Reverts if 'threshold' is less than 1.
     * @param owners The initial set of owners.
     */
    function initializeOwners(bytes[] memory owners, uint8 _threshold) internal virtual {
        uint256 numberOfOwners = owners.length;

        if (numberOfOwners < _threshold || _threshold < 1) revert InvalidThreshold();

        MultiOwnableStorage storage $ = getMultiOwnableStorage();

        uint256 nextOwnerIndex_ = $.nextOwnerIndex;

        uint256 index;
        bytes memory owner;
        for (uint256 i; i < numberOfOwners; i++) {
            owner = owners[i];
            index = nextOwnerIndex_++;

            if (owner.length != 32 && owner.length != 64) {
                revert InvalidOwnerBytesLength(owner);
            }

            if (owner.length == 32 && uint256(bytes32(owner)) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(owner);
            }

            $.isOwner[owner] = true;
            $.ownerAtIndex[index] = owner;

            emit AddOwner(index, owner);
        }

        $.nextOwnerIndex = nextOwnerIndex_;
        $.threshold = _threshold;
    }

    /// @notice Helper function to get a storage reference to the `MultiOwnableStorage` struct.
    function getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
        }
    }

    function authorizeUpdate() internal virtual;
}
