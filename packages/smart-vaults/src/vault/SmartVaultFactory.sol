// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { SmartVault } from "./SmartVault.sol";
import { LibClone } from "solady/utils/LibClone.sol";

/**
 * @title Smart Vault Factory
 *
 * @notice based on Coinbase's Smart Wallet Factory.
 * @author Splits
 */
contract SmartVaultFactory {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable implementation;

    /// @notice Thrown when trying to create a new `SmartVault` account without any owner.
    error OwnerRequired();

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor() payable {
        implementation = address(new SmartVault(address(this)));
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Returns the deterministic address for a Splits Smart Vault created with `root`, `owners` and `nonce`
     *         deploys and initializes contract if it has not yet been created.
     *
     * @dev Deployed as a ERC-1967 proxy that's implementation is `this.implementation`.
     *
     * @param root Root owner of the smart vault.
     * @param owners Array of initial owners. Each item should be an ABI encoded address or 64 byte public key.
     * @param threshold Number of approvals needed for a valid user op/hash.
     * @param nonce  The nonce of the account, a caller defined value which allows multiple accounts
     *               with the same `owners` to exist at different addresses.
     *
     * @return account The address of the ERC-1967 proxy created with inputs `owners`, `nonce`, and
     *                 `this.implementation`.
     */
    function createAccount(
        address root,
        bytes[] calldata owners,
        uint8 threshold,
        uint256 nonce
    )
        external
        payable
        virtual
        returns (SmartVault account)
    {
        if (owners.length == 0) {
            revert OwnerRequired();
        }

        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(root, owners, threshold, nonce));

        account = SmartVault(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(root, owners, threshold);
        }
    }

    /**
     * @notice Returns the deterministic address of the account that would be created by `createAccount`.
     *
     * @param root Root owner of the smart vault.
     * @param owners Array of initial owners. Each item should be an ABI encoded address or 64 byte public key.
     * @param threshold Number of approvals needed for a valid user op/hash.
     * @param nonce  The nonce provided to `createAccount()`.
     *
     * @return The predicted account deployment address.
     */
    function getAddress(
        address root,
        bytes[] calldata owners,
        uint8 threshold,
        uint256 nonce
    )
        external
        view
        returns (address)
    {
        return LibClone.predictDeterministicAddress(
            initCodeHash(), _getSalt(root, owners, threshold, nonce), address(this)
        );
    }

    /**
     * @notice Returns the initialization code hash of the account:
     *         a ERC1967 proxy that's implementation is `this.implementation`.
     *
     * @return The initialization code hash.
     */
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    /// @notice Returns the create2 salt for `LibClone.predictDeterministicAddress`
    function _getSalt(
        address root,
        bytes[] calldata owners,
        uint8 threshold,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(root, owners, threshold, nonce));
    }
}
