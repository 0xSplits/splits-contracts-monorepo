// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { Pausable } from "../../src/utils/Pausable.sol";
import { BaseTest } from "../Base.t.sol";

contract PausableHandler is Pausable {
    constructor(address _owner) {
        __initPausable(_owner, false);
    }

    function test() public view pausable returns (bool) {
        return true;
    }
}

contract PausableTest is BaseTest {
    PausableHandler private pausable;

    error Paused();
    error Unauthorized();

    event SetPaused(bool paused);

    function setUp() public override {
        super.setUp();

        pausable = new PausableHandler(ALICE.addr);
    }

    function test_paused_whenInitialized() public {
        assertEq(pausable.paused(), false);
    }

    function test_revert_whenPaused() public {
        vm.prank(ALICE.addr);
        pausable.setPaused(true);

        vm.expectRevert(Paused.selector);
        pausable.test();
    }

    function test_setPaused(bool _paused) public {
        vm.expectEmit();
        emit SetPaused(_paused);
        vm.prank(ALICE.addr);
        pausable.setPaused(_paused);

        assertEq(pausable.paused(), _paused);
    }

    function test_setPaused_Revert_Unauthorized() public {
        vm.expectRevert(Unauthorized.selector);
        pausable.setPaused(true);
    }
}
