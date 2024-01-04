// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

library Address {
    function balanceOf(address token, address account) internal view returns (uint256) {
        if (token == 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE) {
            return account.balance;
        } else {
            return IERC20(token).balanceOf(account);
        }
    }
}
