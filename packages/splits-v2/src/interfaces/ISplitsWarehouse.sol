// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC6909 } from "./IERC6909.sol";

interface ISplitsWarehouse is IERC6909 {
    function NATIVE_TOKEN() external view returns (address);

    function deposit(address owner, address token, uint256 amount) external payable;

    function batchTransfer(address[] memory recipients, address token, uint256[] memory amounts) external;

    function withdraw(address owner, address token) external;
}
