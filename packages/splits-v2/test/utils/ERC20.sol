// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { ERC20 as AbstractERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ERC20 is AbstractERC20 {
    constructor(string memory name_, string memory symbol_) AbstractERC20(name_, symbol_) { }
}
