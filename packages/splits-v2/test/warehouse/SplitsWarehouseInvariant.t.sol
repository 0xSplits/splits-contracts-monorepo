// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { Cast } from "../../src/libraries/Cast.sol";
import { SplitsWarehouseHandler } from "./SplitsWarehouseHandler.sol";

import { BaseTest } from "../Base.t.sol";

contract SplitsWarehouseInvariantTest is BaseTest {
    using Cast for address;

    SplitsWarehouseHandler private handler;

    function setUp() public override {
        super.setUp();

        address[5] memory users = [ALICE.addr, BOB.addr, CAROL.addr, BAD_ACTOR, DAN.addr];
        address[2] memory tokens = [address(usdc), native];

        handler = new SplitsWarehouseHandler(address(warehouse), ALICE.addr, tokens, users, BAD_ACTOR);

        targetContract(address(handler));
    }

    function invariant_totalSupply() public {
        uint256 usdcTotalSupply = warehouse.totalSupply(address(usdc).toUint256());
        uint256 nativeTotalSupply = warehouse.totalSupply(native.toUint256());

        assertEq(usdcTotalSupply, usdc.balanceOf(address(warehouse)));
        assertEq(nativeTotalSupply, address(warehouse).balance);
    }
}
