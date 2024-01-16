// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

library Math {
    function sum(uint256[] calldata values) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length;) {
            total += values[i];
            unchecked {
                ++i;
            }
        }
    }

    function sumMem(uint256[] memory values) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length;) {
            total += values[i];
            unchecked {
                ++i;
            }
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
