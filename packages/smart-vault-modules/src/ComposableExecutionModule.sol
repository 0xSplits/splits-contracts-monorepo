// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import {
    ComposableExecution,
    Execution,
    InputParam,
    OutputParam
} from "src/vendor/composability/ComposabilityDataTypes.sol";
import { ComposableExecutionLib } from "src/vendor/composability/ComposableExecutionLib.sol";

/**
 * @title Composable Execution Module
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice ERC-8211 smart batching executor for SmartVault accounts. Each batch entry resolves its parameters at
 *         execution time (raw bytes, static calls, or live balances), validates them against inline constraints,
 *         and executes through the calling vault. Entries execute strictly in order, so a later entry's fetchers
 *         observe the effects of earlier entries.
 * @dev The account to execute for is always `msg.sender`; there is no account parameter. The intended flow is a
 *      signed user operation calling `vault.execute(module, executeComposable(...))`, so the module sees the vault
 *      as `msg.sender` and loops back via `executeFromModule`, where the vault's `onlyModule` check applies. A
 *      direct caller can therefore only ever execute for itself. The module is stateless and holds no assets, so
 *      reentrancy by a malicious target only lets that target execute for itself.
 */
contract ComposableExecutionModule {
    using ComposableExecutionLib for InputParam[];
    using ComposableExecutionLib for OutputParam[];

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Emitted after a composable batch executes for an account.
    /// @param account The SmartVault account the batch executed for.
    /// @param executions The number of entries in the batch.
    event ExecutedComposable(address indexed account, uint256 executions);

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Executes a composable batch for `msg.sender`.
     * @dev Per entry: resolve inputs (validating constraints), execute via `executeFromModule` on the caller, then
     *      capture outputs. An entry that resolves to `target == address(0)` is a predicate-only check and skips
     *      execution. Any constraint failure or call revert aborts the entire batch atomically.
     * @param executions_ The composable batch entries to execute in order.
     */
    function executeComposable(ComposableExecution[] calldata executions_) external {
        uint256 length = executions_.length;

        for (uint256 i; i < length; i++) {
            ComposableExecution calldata execution = executions_[i];
            Execution memory resolved = execution.inputParams.processInputs(execution.functionSig);

            if (resolved.target != address(0)) {
                ISmartVault(msg.sender)
                    .executeFromModule(
                        Call({ target: resolved.target, value: resolved.value, data: resolved.callData })
                    );
            }

            execution.outputParams.processOutputs("", msg.sender);
        }

        emit ExecutedComposable(msg.sender, length);
    }
}
