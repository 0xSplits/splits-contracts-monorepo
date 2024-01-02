// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library Cast {
    function toAddress(uint256 value) internal pure returns (address) {
        return address(uint160(value));
    }
}
