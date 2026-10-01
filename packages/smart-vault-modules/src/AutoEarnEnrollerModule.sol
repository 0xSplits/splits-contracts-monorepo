// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";

/**
 * @title Auto Earn Enroller Module
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Enables the auto earn module on a Treasury SmartVault, or on any SmartVault the Treasury owns.
 * @dev A Treasury is a workspace's main SmartVault. Its sub-accounts are the SmartVaults whose `owner()` is the
 *      Treasury. This module is installed on a Treasury via `enableModule`. Once enabled, anyone can call `enroll`
 *      to enable `AUTO_EARN_MODULE` on the Treasury or on one of its sub-accounts, including sub-accounts created
 *      later. Security is enforced by the `onlyModule` modifier inside `SmartVault.executeFromModule`, and by the
 *      sub-account's `onlyEntryPointOrOwner` modifier on `execute`.
 *      To turn auto earn off, also disable this module on the Treasury, or anyone can re-enroll its accounts.
 */
contract AutoEarnEnrollerModule {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when a zero address is provided.
    error ZeroAddress();

    /// @notice Thrown when the account has no code on this chain.
    error AccountNotDeployed();

    /// @notice Thrown when the Treasury has no code on this chain.
    error TreasuryNotDeployed();

    /// @notice Thrown when the account is neither the Treasury nor owned by the Treasury.
    error NotOwnedByTreasury();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Emitted when the auto earn module is enabled on an account.
    /// @dev Anyone can trigger this for any contract that reports the Treasury as its `owner()`, so only trust it for
    ///      accounts known to be in the workspace.
    /// @param treasury The Treasury that executed the enrollment.
    /// @param account The account the auto earn module was enabled on.
    event Enrolled(address indexed treasury, address indexed account);

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice The auto earn module that `enroll` enables on accounts.
    address public immutable AUTO_EARN_MODULE;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @param autoEarnModule_ The auto earn module address.
     */
    constructor(address autoEarnModule_) {
        if (autoEarnModule_ == address(0)) revert ZeroAddress();

        AUTO_EARN_MODULE = autoEarnModule_;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Enables the auto earn module on `account_`.
     * @dev The Treasury enables the module on itself directly. For a sub-account, the Treasury calls the
     *      sub-account's `execute` (allowed because the Treasury is its owner), and the sub-account enables the
     *      module on itself. Both are dispatched through the Treasury's `executeFromModule`.
     *      Callable by anyone — access control is enforced by the Treasury's `onlyModule` modifier.
     *      After the deployment and ownership checks, if the auto earn module is already enabled on `account_`, this
     *      function is a no-op (returns silently) so that batched calls do not revert on accounts that are already
     *      enrolled. The no-op does not call the Treasury, so it succeeds even if this module is not enabled there.
     * @param treasury_ The Treasury that has this module enabled.
     * @param account_ The Treasury itself, or a SmartVault owned by the Treasury.
     */
    function enroll(ISmartVault treasury_, ISmartVault account_) external {
        // These checks give descriptive reverts. Access control itself is enforced by the SmartVault modifiers.
        if (address(account_).code.length == 0) revert AccountNotDeployed();
        if (address(treasury_).code.length == 0) revert TreasuryNotDeployed();

        bool isTreasury = address(account_) == address(treasury_);
        if (!isTreasury && account_.owner() != address(treasury_)) revert NotOwnedByTreasury();

        if (account_.isModuleEnabled(AUTO_EARN_MODULE)) return;

        Call memory enableModuleCall = Call({
            target: address(account_), value: 0, data: abi.encodeCall(ISmartVault.enableModule, (AUTO_EARN_MODULE))
        });

        Call[] memory calls = new Call[](1);
        if (isTreasury) {
            calls[0] = enableModuleCall;
        } else {
            calls[0] = Call({
                target: address(account_), value: 0, data: abi.encodeCall(ISmartVault.execute, (enableModuleCall))
            });
        }

        treasury_.executeFromModule(calls);

        emit Enrolled(address(treasury_), address(account_));
    }
}
