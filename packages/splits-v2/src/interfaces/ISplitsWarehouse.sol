// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

interface ISplitsWarehouse {
    function NATIVE_TOKEN() external view returns (address);

    function deposit(address _owner, address _token, uint256 _amount) external payable;

    function deposit(address[] calldata _owners, address _token, uint256[] calldata _amounts) external payable;

    function depositAfterTransfer(address _owner, address _token, uint256 _amount) external;

    function depositAfterTransfer(address[] calldata _owners, address _token, uint256[] calldata _amounts) external;

    function withdraw(address _token, uint256 _amount) external;

    function withdraw(address[] memory _tokens, uint256[] memory _amounts) external;

    function withdraw(address _owner, address _token, uint256 _amount) external;

    function withdraw(address _owner, address[] calldata _tokens, uint256[] calldata _amounts) external;
}
