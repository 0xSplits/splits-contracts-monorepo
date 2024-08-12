// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { SmartVault } from "./SmartVault.sol";

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { LibClone } from "solady/utils/LibClone.sol";

/**
 * @title Splits Smart Accounts/Vaults Factory
 * @notice based on Coinbase's Smart Wallet Factory.
 * @author Splits (https://splits.org)
 */
contract SmartVaultFactory {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable IMPLEMENTATION;

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SmartVaultCreated(address indexed vault, address owner, bytes[] signers, uint8 threshold, uint256 salt);

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor() payable {
        IMPLEMENTATION = address(new SmartVault());
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Returns the deterministic address for a Splits Smart Vault created with `owner`, `signers`, 'threshold',
     * `salt`. Deploys and initializes contract if it has not yet been created.
     *
     * @dev Deployed as an ERC-1967 proxy.
     *
     * @param owner_ Owner of the smart vault.
     * @param signers_ Array of initial signers. Each item should be an ABI encoded address or 64 byte public key.
     * @param threshold_ Number of approvals needed for a valid user op/hash.
     * @param salt_  The salt of the account, a caller defined value which allows multiple accounts
     *               with the same `signers` to exist at different addresses.
     *
     * @return account The address of the ERC-1967 proxy created.
     */
    function createAccount(
        address owner_,
        bytes[] calldata signers_,
        uint8 threshold_,
        uint256 salt_
    )
        external
        payable
        virtual
        returns (SmartVault account)
    {
        (bool alreadyDeployed, address accountAddress) = LibClone.createDeterministicERC1967(
            msg.value, IMPLEMENTATION, _getSalt(owner_, signers_, threshold_, salt_)
        );

        account = SmartVault(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(owner_, signers_, threshold_);

            emit SmartVaultCreated({
                vault: accountAddress,
                owner: owner_,
                signers: signers_,
                threshold: threshold_,
                salt: salt_
            });
        }
    }

    /**
     * @notice Returns the deterministic address of the account that would be created by `createAccount`.
     *
     * @dev Reverts when the initial configuration of signers is invalid.
     *
     * @param owner_ Owner of the smart vault.
     * @param signers_ Array of initial signers. Each item should be an ABI encoded address or 64 byte public key.
     * @param threshold_ Number of approvals needed for a valid user op/hash.
     * @param salt_  The salt provided to `createAccount()`.
     *
     * @return The predicted account deployment address.
     */
    function getAddress(
        address owner_,
        bytes[] calldata signers_,
        uint8 threshold_,
        uint256 salt_
    )
        external
        view
        returns (address)
    {
        MultiSignerLib.validateSigners(signers_, threshold_);
        return LibClone.predictDeterministicAddress(
            initCodeHash(), _getSalt(owner_, signers_, threshold_, salt_), address(this)
        );
    }

    /**
     * @notice Returns the initialization code hash of the account:
     *         a ERC1967 proxy that's implementation is `IMPLEMENTATION`.
     *
     * @return The initialization code hash.
     */
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(IMPLEMENTATION);
    }

    /* -------------------------------------------------------------------------- */
    /*                          INTERNAL/PRIVATE FUNCTION                         */
    /* -------------------------------------------------------------------------- */

    /// @notice Returns the create2 salt for `LibClone.predictDeterministicAddress`
    function _getSalt(
        address owner_,
        bytes[] calldata signers_,
        uint8 threshold_,
        uint256 salt_
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(owner_, signers_, threshold_, salt_));
    }
}
