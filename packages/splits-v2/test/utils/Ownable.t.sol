// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Ownable } from "../../src/utils/Ownable.sol";
import { BaseTest } from "../Base.t.sol";

contract OwnableHandler is Ownable {
    constructor(address _owner) {
        __initOwnable(_owner);
    }
}

contract OwnableTest is BaseTest {
    OwnableHandler ownable;

    error Unauthorized();

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function setUp() public override {
        super.setUp();

        ownable = new OwnableHandler(ALICE.addr);
    }

    function test_owner() public {
        assertEq(ownable.owner(), ALICE.addr);
    }

    function test_transferOwnership() public {
        vm.expectEmit();
        emit OwnershipTransferred(ALICE.addr, BOB.addr);
        vm.prank(ownable.owner());
        ownable.transferOwnership(BOB.addr);

        assertEq(ownable.owner(), BOB.addr);
    }

    function test_transferOwnership_Revert_Unauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        ownable.transferOwnership(BOB.addr);
    }
}
