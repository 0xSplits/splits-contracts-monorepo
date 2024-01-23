// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IERC6909XCallback {
    function onTemporaryApprove(
        address owner,
        bool operator,
        uint256 id,
        uint256 amount,
        bytes calldata data
    )
        external
        returns (bytes4);
}