// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";

contract WarehouseTest is BaseTest {
    function test_name_returnsWrappedName() public {
        assertEq(warehouse.name(tokenToId(address(usdc))), string.concat("Splits Wrapped ", usdc.name()));
    }

    function test_symbol_returnsWrappedSymbol() public {
        assertEq(warehouse.symbol(tokenToId(address(usdc))), string.concat("Splits", usdc.symbol()));
    }

    function test_name_whenNativeToken_returnsWrappedName() public {
        assertEq(warehouse.name(warehouse.GAS_TOKEN_ID()), string.concat("Splits Wrapped Ether"));
    }

    function test_symbol_whenNativeToken_returnsWrappedSymbol() public {
        assertEq(warehouse.symbol(warehouse.GAS_TOKEN_ID()), string.concat("SplitsETH"));
    }
}
