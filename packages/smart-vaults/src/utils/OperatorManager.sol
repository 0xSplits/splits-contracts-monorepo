// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Caller } from "./Caller.sol";

/**
 * @title Operator Manager
 * @notice Manages operators of a smart contract. Gives each operator the ability to execute `Calls` from this account.
 * @dev Account owners should be careful when adding an operator.
 */
abstract contract OperatorManager is Caller {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `OperatorManager` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.operatorManager")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 internal constant _OPERATOR_MANAGER_STORAGE_SLOT =
        0x0216194314f4301bb656e2100094647329591429172ab63bdb3b133cea9bbf00;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Operator Manager storage structure.
    struct OperatorManagerStorage {
        mapping(address => bool) isOperator;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Event emitted when an operator is added.
    event OperatorAdded(address indexed operator);

    /// @notice Event emitted when an operator is removed.
    event OperatorRemoved(address indexed operator);

    /// @notice Event emitted when an operator executes a call.
    event ExecutedTxFromOperator(address indexed operator, Call call);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when caller is not an operator.
    error OnlyOperator();

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyOperator() {
        if (!_getOperatorManagerStorage().isOperator[msg.sender]) revert OnlyOperator();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds operator to the allowlist.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param operator_ address of operator.
     */
    function addOperator(address operator_) public {
        _authorize();

        _addOperator(operator_);
    }

    /**
     * @notice Adds `operator` to the allowlist and makes a call to the `setupContract` passing `data_`.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param operator_ address of operator.
     * @param setupContract_ address of contract to call to setup operator.
     * @param data_ data passed to the setupContract.
     */
    function addAndSetupOperator(address operator_, address setupContract_, bytes calldata data_) public {
        _authorize();

        _addOperator(operator_);

        _call(setupContract_, 0, data_);
    }

    /**
     * @notice Removes operator from the allowlist.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param operator_ address of operator.
     */
    function removeOperator(address operator_) public {
        _authorize();

        _removeOperator(operator_);
    }

    /**
     * @notice Removes `operator` from the allowlist and makes a call to the `teardownContract_` passing `data_`.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param operator_ address of operator.
     * @param teardownContract_ address of contract to call to teardown operator.
     * @param data_ data passed to the setupContract.
     */
    function removeAndTeardownOperator(address operator_, address teardownContract_, bytes calldata data_) public {
        _authorize();

        _removeOperator(operator_);

        _call(teardownContract_, 0, data_);
    }

    /**
     * @notice Executes a single call from the account.
     *
     * @dev Can only be called by the operator.
     * @dev Emits an event to capture the call executed.
     *
     * @param call_ Call to execute from the account.
     */
    function executeFromOperator(Call calldata call_) external onlyOperator {
        _call(call_.target, call_.value, call_.data);

        emit ExecutedTxFromOperator(msg.sender, call_);
    }

    /**
     * @notice Executes calls from the account.
     *
     * @dev Can only be called by the operator.
     * @dev Emits an event to capture the call executed.
     *
     * @param calls_ Calls to execute from this account.
     */
    function executeFromOperator(Call[] calldata calls_) external onlyOperator {
        uint256 numCalls = calls_.length;

        for (uint256 i; i < numCalls; i++) {
            _call(calls_[i]);

            emit ExecutedTxFromOperator(msg.sender, calls_[i]);
        }
    }

    /**
     * @notice Returns true if the provided `operator` is added otherwise false.
     *
     * @param operator_ address of operator.
     */
    function isOperator(address operator_) public view returns (bool) {
        return _getOperatorManagerStorage().isOperator[operator_];
    }

    /* -------------------------------------------------------------------------- */
    /*                         INTERNAL/PRIVATE FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _addOperator(address operator_) public {
        _getOperatorManagerStorage().isOperator[operator_] = true;

        emit OperatorAdded(operator_);
    }

    function _removeOperator(address operator_) public {
        _getOperatorManagerStorage().isOperator[operator_] = false;

        emit OperatorRemoved(operator_);
    }

    function _authorize() internal view virtual;

    function _getOperatorManagerStorage() internal pure returns (OperatorManagerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _OPERATOR_MANAGER_STORAGE_SLOT
        }
    }
}
