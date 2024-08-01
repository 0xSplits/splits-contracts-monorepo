// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Caller } from "src/utils/Caller.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

contract MockTransferOperator {
    event AccountAdded(address account);
    event AccountRemoved(address account);

    function transfer(SmartVault account, address token, uint256 amount, address to) public {
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);

        Caller.Call memory call = Caller.Call(token, 0, data);

        account.executeFromOperator(call);
    }

    function transfer(SmartVault account, uint256 amount, address to) public {
        bytes memory data;
        Caller.Call memory call = Caller.Call(to, amount, data);
        account.executeFromOperator(call);
    }

    function transfer(SmartVault account, uint96 amount1, address to1, uint96 amount2, address to2) public {
        bytes memory data;
        Caller.Call[] memory calls = new Caller.Call[](2);
        calls[0] = Caller.Call(to1, amount1, data);
        calls[1] = Caller.Call(to2, amount2, data);
        account.executeFromOperator(calls);
    }

    function addAccount() public {
        emit AccountAdded(msg.sender);
    }

    function removeAccount() public {
        emit AccountRemoved(msg.sender);
    }
}
