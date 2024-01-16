// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { Ownable } from "./Ownable.sol";

/**
 * @title Wallet Implementation
 * @author 0xSplits
 * @notice Minimal smart wallet clone-implementation
 */
abstract contract Wallet is Ownable {
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

    function __initWallet(address owner_) internal {
        Ownable.__initOwnable(owner_);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTONS                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Execute a batch of calls
     * @dev The calls are executed in order, reverting if any of them fails, can only be called by the owner
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
        for (uint256 i; i < length;) {
            Call calldata calli = _calls[i];
            (success, returnData[i]) = calli.to.call{ value: calli.value }(calli.data);

            // solhint-disable-next-line
            require(success, string(returnData[i]));

            unchecked {
                ++i;
            }
        }

        emit ExecCalls(_calls);
    }
}
