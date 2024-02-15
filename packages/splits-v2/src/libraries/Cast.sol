// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

library Cast {
    error Overflow();

    function toAddress(uint256 _value) internal pure returns (address) {
        return address(toUint160(_value));
    }

    function toUint256(address _value) internal pure returns (uint256) {
        return uint256(uint160(_value));
    }

    function toUint160(uint256 _x) internal pure returns (uint160 y) {
        if (_x >> 160 != 0) revert Overflow();
        // solhint-disable-next-line no-inline-assembly
        assembly {
            y := _x
        }
    }
}
