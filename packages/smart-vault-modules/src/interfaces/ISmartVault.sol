// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @notice A low-level call to execute on behalf of an account.
struct Call {
    address target;
    uint256 value;
    bytes data;
}

/// @notice Minimal interface for SmartVault module interactions.
interface ISmartVault {
    /// @notice Executes a batch of calls from an enabled module.
    function executeFromModule(Call[] calldata calls_) external;

    /// @notice Enables a module on the vault. Can only be called by the vault itself.
    function enableModule(address module_) external;

    /// @notice Disables a module on the vault. Can only be called by the vault itself.
    function disableModule(address module_) external;
}
