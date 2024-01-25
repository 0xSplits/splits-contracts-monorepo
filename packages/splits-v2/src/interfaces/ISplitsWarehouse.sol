// SPDX-License-Identifier: UNLICENSED
// license?
pragma solidity ^0.8.18;

import { IERC6909 } from "./IERC6909.sol";

interface ISplitsWarehouse is IERC6909 {
    function NATIVE_TOKEN() external view returns (address);

    function deposit(address _owner, address _token, uint256 _amount) external payable;

    function batchTransfer(address _token, address[] memory _recipients, uint256[] memory _amounts) external;

    function withdraw(address _owner, address _token) external;
}
