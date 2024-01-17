// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

interface ISplitsWarehouse {
    function NATIVE_TOKEN() external view returns (address);

    function deposit(address _owner, address _token, uint256 _amount) external payable;

    function batchTransfer(address _token, address[] memory _recipients, uint256[] memory _amounts) external;
}
