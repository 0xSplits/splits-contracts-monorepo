// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Caller } from "./Caller.sol";

/**
 * @title Module Manager
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Manages modules of a smart contract. Gives each module the ability to execute `Calls` from this account.
 * @dev Account owners should be careful when adding a module.
 */
abstract contract ModuleManager is Caller {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `ModuleManager` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.moduleManager")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 internal constant _MODULE_MANAGER_STORAGE_SLOT =
        0xe103b19f601cd46db3208af0dd24bb7e0acd21ca997b18cc4246bfe5258d3800;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Module Manager storage structure.
    /// @custom:storage-location erc7201:splits.storage.moduleManager
    struct ModuleManagerStorage {
        mapping(address => bool) isModule;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Event emitted when an module is enabled.
    event EnabledModule(address indexed module);

    /// @notice Event emitted when an module is disabled.
    event DisabledModule(address indexed module);

    /// @notice Event emitted when an module executes a call.
    event ExecutedTxFromModule(address indexed module, Call call);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when caller is not an module.
    error OnlyModule();

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyModule() {
        if (!_getModuleManagerStorage().isModule[msg.sender]) revert OnlyModule();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Adds `module` to the allowlist.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param module_ address of module.
     */
    function enableModule(address module_) external {
        _authorize();

        _enableModule(module_);
    }

    /**
     * @notice Adds `module` to the allowlist and makes a call to the `setupContract` passing `data_`.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param module_ address of module.
     * @param setupContract_ address of contract to call to setup module.
     * @param data_ data passed to the setupContract.
     */
    function setupAndEnableModule(address module_, address setupContract_, bytes calldata data_) external {
        _authorize();

        _enableModule(module_);

        _call(setupContract_, 0, data_);
    }

    /**
     * @notice Removes module from the allowlist.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param module_ address of module.
     */
    function disableModule(address module_) external {
        _authorize();

        _disableModule(module_);
    }

    /**
     * @notice Removes `module` from the allowlist and makes a call to the `teardownContract_` passing `data_`.
     *
     * @dev access is controlled by `_authorize()`
     *
     * @param module_ address of module.
     * @param teardownContract_ address of contract to call to teardown module.
     * @param data_ data passed to the teardown contract.
     */
    function teardownAndDisableModule(address module_, address teardownContract_, bytes calldata data_) external {
        _authorize();

        _disableModule(module_);

        _call(teardownContract_, 0, data_);
    }

    /**
     * @notice Executes a single call from the account.
     *
     * @dev Can only be called by a module present in the allowlist.
     * @dev Emits an event to capture the call executed.
     *
     * @param call_ Call to execute from the account.
     */
    function executeFromModule(Call calldata call_) external onlyModule {
        _call(call_);

        emit ExecutedTxFromModule(msg.sender, call_);
    }

    /**
     * @notice Executes calls from the account.
     *
     * @dev Can only be called by a module present in the allowlist.
     * @dev Emits an event to capture the call executed.
     *
     * @param calls_ Calls to execute from this account.
     */
    function executeFromModule(Call[] calldata calls_) external onlyModule {
        uint256 numCalls = calls_.length;

        for (uint256 i; i < numCalls; i++) {
            _call(calls_[i]);

            emit ExecutedTxFromModule(msg.sender, calls_[i]);
        }
    }

    /**
     * @notice Returns true if the provided `module` is enabled otherwise false.
     *
     * @param module_ address of module.
     */
    function isModuleEnabled(address module_) external view returns (bool) {
        return _getModuleManagerStorage().isModule[module_];
    }

    /* -------------------------------------------------------------------------- */
    /*                         INTERNAL/PRIVATE FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _enableModule(address module_) internal {
        _getModuleManagerStorage().isModule[module_] = true;

        emit EnabledModule(module_);
    }

    function _disableModule(address module_) internal {
        _getModuleManagerStorage().isModule[module_] = false;

        emit DisabledModule(module_);
    }

    function _authorize() internal view virtual;

    function _getModuleManagerStorage() internal pure returns (ModuleManagerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _MODULE_MANAGER_STORAGE_SLOT
        }
    }
}
