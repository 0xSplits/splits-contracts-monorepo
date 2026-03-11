// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC20 } from "src/interfaces/IERC20.sol";
import { IERC4626 } from "src/interfaces/IERC4626.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";

/**
 * @title Auto Earn Module
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Automatically deposits idle ERC-20 tokens into an ERC-4626 earn vault on behalf of a SmartVault account.
 * @dev This module is installed on a SmartVault via `enableModule`. Once enabled, anyone can call `deposit` to sweep
 *      the account's full token balance into the configured vault. Security is enforced by the `onlyModule`
 *      modifier inside `SmartVault.executeFromModule`.
 */
contract AutoEarnModule {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when a zero address is provided.
    error ZeroAddress();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Emitted when tokens are deposited into the earn vault on behalf of an account.
    /// @param account The SmartVault account that deposited.
    /// @param amount The token amount deposited.
    event Deposited(address indexed account, uint256 amount);

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice The ERC-20 token address.
    address public immutable ASSET;

    /// @notice The ERC-4626 earn vault address.
    address public immutable VAULT;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @param asset_ The ERC-20 token address.
     * @param vault_ The ERC-4626 earn vault address.
     */
    constructor(address asset_, address vault_) {
        if (asset_ == address(0) || vault_ == address(0)) revert ZeroAddress();

        ASSET = asset_;
        VAULT = vault_;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Deposits the full token balance of `account_` into the earn vault.
     * @dev Constructs two calls (approve + deposit) and executes them atomically via `executeFromModule`.
     *      Callable by anyone — access control is enforced by the SmartVault's `onlyModule` modifier.
     *      If the account has no balance, this function is a no-op (returns silently) so that batched
     *      calls do not revert when one account has zero balance.
     * @param account_ The SmartVault account to deposit tokens from.
     */
    function deposit(ISmartVault account_) external {
        uint256 balance = IERC20(ASSET).balanceOf(address(account_));
        if (balance == 0) return;

        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: ASSET, value: 0, data: abi.encodeCall(IERC20.approve, (VAULT, balance)) });
        calls[1] =
            Call({ target: VAULT, value: 0, data: abi.encodeCall(IERC4626.deposit, (balance, address(account_))) });

        account_.executeFromModule(calls);

        emit Deposited(address(account_), balance);
    }
}
