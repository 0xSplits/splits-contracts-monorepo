// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

library Cast {
    function toAddress(uint256 value) internal pure returns (address) {
        return address(uint160(value));
    }

    function toUint256(address value) internal pure returns (uint256) {
        return uint256(uint160(value));
    }
}
