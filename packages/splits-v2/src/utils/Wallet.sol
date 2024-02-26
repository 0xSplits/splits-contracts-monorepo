// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Pausable } from "./Pausable.sol";

import { ERC1155Holder } from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import { ERC721Holder } from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";

/**
 * @title Wallet Implementation
 * @author Splits
 * @notice Minimal smart wallet clone-implementation.
 */
abstract contract Wallet is Pausable, ERC721Holder, ERC1155Holder {
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
        returns (uint256 blockNumber, bytes[] memory returnData)
    {
        address caller = msg.sender;
        blockNumber = block.number;
        uint256 length = _calls.length;
        returnData = new bytes[](length);

        bool success;
        for (uint256 i; i < length; ++i) {
            // prevent user from executing calls after transferring ownership.
            if (caller != owner) revert Unauthorized();

            Call calldata calli = _calls[i];

            if (calli.to.code.length == 0) {
                // When the call is to an EOA, the calldata must be empty.
                if (calli.data.length > 0) revert InvalidCalldataForEOA({ call: calli });
            }

            (success, returnData[i]) = calli.to.call{ value: calli.value }(calli.data);

            // solhint-disable-next-line
            require(success, string(returnData[i]));
        }

        emit ExecCalls({ calls: _calls });
    }
}
