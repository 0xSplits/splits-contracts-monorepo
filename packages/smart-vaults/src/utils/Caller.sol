// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/**
 * @title Caller contract
 * @notice Contract that provides basic functionalities to make external calls from a smart contract.
 */
contract Caller {
    /// @notice Represents a call to execute.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /* -------------------------------------------------------------------------- */
    /*                         INTERNAL/PRIVATE FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _call(address target_, uint256 value_, bytes calldata data_) internal {
        (bool success, bytes memory result) = target_.call{ value: value_ }(data_);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _call(Call calldata call_) internal {
        _call(call_.target, call_.value, call_.data);
    }
}
