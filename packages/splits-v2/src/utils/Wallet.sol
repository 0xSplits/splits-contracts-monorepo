// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Ownable } from "./Ownable.sol";

/// @title Wallet Implementation
/// @author 0xSplits
/// @notice Minimal smart wallet clone-implementation
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
    constructor() { }

    function __initWallet(address owner_) internal {
        Ownable.__initOwnable(owner_);
    }

    /// -----------------------------------------------------------------------
    /// functions - external & public - onlyOwner
    /// -----------------------------------------------------------------------

    /// allow owner to execute arbitrary calls
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
            require(success, string(returnData[i]));

            unchecked {
                ++i;
            }
        }

        emit ExecCalls(_calls);
    }
}
