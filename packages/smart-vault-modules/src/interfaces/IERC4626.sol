// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @notice Minimal ERC-4626 interface.
interface IERC4626 {
    /// @notice Deposits `assets` into the vault, minting shares to `receiver`.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}
