// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library Math {
    function sum(uint256[] calldata values) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length; i++) {
            total += values[i];
        }
    }

    function sumMem(uint256[] memory values) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length; i++) {
            total += values[i];
        }
    }
}
