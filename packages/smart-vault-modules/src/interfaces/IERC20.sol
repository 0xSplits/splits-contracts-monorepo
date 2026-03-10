// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @notice Minimal ERC-20 interface.
interface IERC20 {
    /// @notice Returns the token balance of `account`.
    function balanceOf(address account) external view returns (uint256);

    /// @notice Approves `spender` to transfer up to `amount` tokens.
    function approve(address spender, uint256 amount) external returns (bool);
}
