// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitsWarehouse } from "../../src/SplitsWarehouse.sol";
import { IERC6909XCallback } from "../../src/interfaces/IERC6909XCallback.sol";

contract ERC6909Callback is IERC6909XCallback {
    bytes4 public constant CALLBACK_SELECTOR = this.onTemporaryApprove.selector;

    function onTemporaryApprove(
        address owner,
        bool isOperator,
        uint256 id,
        uint256 amount,
        bytes calldata
    )
        external
        view
        override
        returns (bytes4)
    {
        require(SplitsWarehouse(msg.sender).allowance(owner, address(this), id) == amount);
        require(SplitsWarehouse(msg.sender).isOperator(owner, address(this)) == isOperator);
        return CALLBACK_SELECTOR;
    }
}
