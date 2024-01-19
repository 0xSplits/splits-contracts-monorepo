// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

library Cast {
    error Overflow();

    function toAddress(uint256 value) internal pure returns (address) {
        return address(toUint160(value));
    }

    function toUint256(address value) internal pure returns (uint256) {
        return uint256(uint160(value));
    }

    function toUint160(uint256 x) internal pure returns (uint160) {
        if (x >= 1 << 160) revert Overflow();
        return uint160(x);
    }
}
