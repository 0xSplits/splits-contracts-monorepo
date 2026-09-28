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

    /// @notice Executes a call from the vault. Can only be called by the EntryPoint or the vault's owner.
    function execute(Call calldata call_) external payable;

    /// @notice Returns true if `module_` is enabled on the vault.
    function isModuleEnabled(address module_) external view returns (bool);

    /// @notice Returns the owner of the vault.
    function owner() external view returns (address);
}
