// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { StorageSlot } from "@openzeppelin/contracts/utils/StorageSlot.sol";

/**
 * @title Root Owner
 * @notice Provides root owner functionality to the inheriting contract.
 * @author Splits
 */
contract RootOwner {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the root owner in storage.
     *     Computed from keccak256(abi.encode(uint256(keccak256("splits.storage.root")) - 1)) & ~bytes32(uint256(0xff))
     *     Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 private constant ROOT_OWNER_STORAGE_LOCATION =
        0xae7382cdf6e212cea7d670e6804587eb3fdf79e0355f50a38eaf58f88ba29e00;

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Emitted when root is initialized.
    event RootInitialized(address indexed root);

    /// @notice Emitted when root control is transferred.
    event RootControlTransferred(address indexed _oldRoot, address indexed _newRoot);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when the `msg.sender` is not the root and is trying to call a privileged function.
    error OnlyRoot();

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Access control modifier ensuring the caller is the root owner.
    modifier onlyRoot() virtual {
        checkRoot();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns the current root owner.
    function root() public view returns (address) {
        return getRoot();
    }

    /// @notice Transfers root control to `_newRoot`.
    function transferRootControl(address _newRoot) public onlyRoot {
        emit RootControlTransferred(getRoot(), _newRoot);

        setRoot(_newRoot);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initialize the root owner of this contract.
     * @dev Intended to be called contract is first deployed and never again.
     * @param _root The root owner of this contract.
     */
    function initializeRoot(address _root) internal virtual {
        setRoot(_root);

        emit RootInitialized(_root);
    }

    /// @notice Checks if the sender is the root owner of this contract or the contract itself when root is zero.
    function checkRoot() internal view virtual {
        address root_ = getRoot();
        if (msg.sender == root_ || (root_ == address(0) && msg.sender == address(this))) {
            return;
        }

        revert OnlyRoot();
    }

    function getRoot() internal view returns (address) {
        return StorageSlot.getAddressSlot(ROOT_OWNER_STORAGE_LOCATION).value;
    }

    function setRoot(address _root) internal {
        StorageSlot.getAddressSlot(ROOT_OWNER_STORAGE_LOCATION).value = _root;
    }
}
