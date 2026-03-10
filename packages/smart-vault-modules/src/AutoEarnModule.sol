// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";

/**
 * @title Auto Earn Module
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Automatically deposits idle USDC into an Aave earn vault on behalf of a SmartVault account.
 * @dev This module is installed on a SmartVault via `enableModule`. Once enabled, anyone can call `deposit` to sweep
 *      the account's full USDC balance into the configured Aave vault. Security is enforced by the `onlyModule`
 *      modifier inside `SmartVault.executeFromModule`.
 */
contract AutoEarnModule {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when the account has no USDC balance to deposit.
    error NoBalance();

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice The USDC token address.
    address public immutable USDC;

    /// @notice The Aave USDC earn vault address.
    address public immutable VAULT;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @param usdc_ The USDC token address.
     * @param vault_ The Aave USDC earn vault address.
     */
    constructor(address usdc_, address vault_) {
        USDC = usdc_;
        VAULT = vault_;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Deposits the full USDC balance of `account_` into the Aave earn vault.
     * @dev Constructs two calls (approve + deposit) and executes them atomically via `executeFromModule`.
     *      Callable by anyone — access control is enforced by the SmartVault's `onlyModule` modifier.
     * @param account_ The SmartVault account to deposit USDC from.
     */
    function deposit(ISmartVault account_) external {
        uint256 balance = IERC20(USDC).balanceOf(address(account_));
        if (balance == 0) revert NoBalance();

        Call[] memory calls = new Call[](2);
        calls[0] = Call({ target: USDC, value: 0, data: abi.encodeCall(IERC20.approve, (VAULT, balance)) });
        calls[1] = Call({
            target: VAULT,
            value: 0,
            data: abi.encodeWithSignature("deposit(uint256,address)", balance, address(account_))
        });

        account_.executeFromModule(calls);
    }
}
