// SPDX-License-Identifier: GPL-3.0-or-later
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

    function invariant_totalBalance() public {
        uint256 usdcTotalBalance = handler.warehouseBalance(address(usdc));
        uint256 nativeTotalBalance = handler.warehouseBalance(address(native));

        assertEq(usdcTotalBalance, usdc.balanceOf(address(warehouse)));
        assertEq(nativeTotalBalance, address(warehouse).balance);
    }
}
