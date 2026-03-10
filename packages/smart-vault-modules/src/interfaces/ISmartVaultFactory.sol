// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @notice A signer slot pair used to initialize a SmartVault.
struct Signer {
    bytes32 slot1;
    bytes32 slot2;
}

/// @notice Minimal interface for the SmartVault factory.
interface ISmartVaultFactory {
    /// @notice Deploys a new SmartVault (or returns an existing deterministic one).
    function createAccount(
        address owner_,
        Signer[] calldata signers_,
        uint8 threshold_,
        uint256 salt_
    )
        external
        payable
        returns (address account);
}
