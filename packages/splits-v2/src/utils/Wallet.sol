// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Pausable } from "./Pausable.sol";

/**
 * @title Wallet Implementation
 * @author 0xSplits
 * @notice Minimal smart wallet clone-implementation.
 */
abstract contract Wallet is Pausable {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidCalldataForEOA(Call call);

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event ExecCalls(Call[] calls);

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    function __initWallet(address _owner) internal {
        __initPausable(_owner, false);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTONS                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Execute a batch of calls.
     * @dev The calls are executed in order, reverting if any of them fails. Can
     * only be called by the owner.
     * @param _calls The calls to execute
     */
    function execCalls(Call[] calldata _calls)
        external
        payable
        onlyOwner
        returns (uint256 blockNumber, bytes[] memory returnData)
    {
        blockNumber = block.number;
        uint256 length = _calls.length;
        returnData = new bytes[](length);

        bool success;
        for (uint256 i; i < length; ++i) {
            Call calldata calli = _calls[i];

            if (calli.to.code.length == 0) {
                if (calli.data.length > 0) revert InvalidCalldataForEOA(calli);
            }

            (success, returnData[i]) = calli.to.call{ value: calli.value }(calli.data);

            // solhint-disable-next-line
            require(success, string(returnData[i]));
        }

        emit ExecCalls(_calls);
    }
}
