// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

library Math {
    function sum(uint256[] calldata values) internal pure returns (uint256 total) {
        for (uint256 i; i < values.length; ++i) {
            total += values[i];
        }
    }

    function sumMem(uint256[] memory values) internal pure returns (uint256 total) {
        for (uint256 i; i < values.length; ++i) {
            total += values[i];
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
