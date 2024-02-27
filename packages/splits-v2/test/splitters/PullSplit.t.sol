// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../../src/libraries/Clone.sol";

import { PullSplit } from "../../src/splitters/pull/PullSplit.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { BaseTest } from "../Base.t.sol";

contract PullSplitTest is BaseTest {
    PullSplit private pullSplit;

    function setUp() public override {
        super.setUp();

        pullSplit = PullSplit(Clone.cloneDeterministic((address(new PullSplit(address(warehouse)))), 0));
    }

    function testFuzz_depositToWarehouse(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        if (_native) deal(address(pullSplit), _amount);
        else deal(_token, address(pullSplit), _amount);

        pullSplit.depositToWarehouse(_token, _amount);

        assertGte(warehouse.balanceOf(address(pullSplit), tokenToId(_token)), _amount);
        if (_native) assertEq(address(pullSplit).balance, 0);
        else assertEq(IERC20(_token).balanceOf(address(pullSplit)), 0);
    }

    function testFuzz_depositToWarehouse_whenApproved(bool _native, uint96 _amount1, uint96 _amount2) public {
        testFuzz_depositToWarehouse(_native, _amount1);
        testFuzz_depositToWarehouse(_native, _amount2);
    }

    function test_depositToWarehouse_Revert_whenInvalidToken() public {
        vm.expectRevert();
        pullSplit.depositToWarehouse(address(0), 0);
    }

    function testFuzz_depositToWarehouse_Revert_whenInvalidAmount(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        dealSplit(address(pullSplit), _token, _amount - 1, 0);

        vm.expectRevert();
        pullSplit.depositToWarehouse(_token, _amount);
    }
}
