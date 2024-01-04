// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Cast } from "../../src/libraries/Cast.sol";
import { WarehouseHandler } from "./WarehouseHandler.sol";

import { BaseTest } from "../Base.t.sol";

contract WarehouseInvariantTest is BaseTest {
    using Cast for address;

    WarehouseHandler handler;

    function setUp() public override {
        super.setUp();

        address[5] memory users = [ALICE, BOB, CAROL, BAD_ACTOR, DAN];
        address[2] memory tokens = [address(usdc), native];

        handler = new WarehouseHandler(address(warehouse), ALICE, tokens, users);

        targetContract(address(handler));
    }

    function invariant_totalSupply() public {
        uint256 usdcTotalSupply = warehouse.totalSupply(address(usdc).toUint256());
        uint256 nativeTotalSupply = warehouse.totalSupply(native.toUint256());

        assertEq(usdcTotalSupply, usdc.balanceOf(address(warehouse)));
        assertEq(nativeTotalSupply, address(warehouse).balance);
    }
}
