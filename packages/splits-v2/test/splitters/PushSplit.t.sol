// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../../src/libraries/Clone.sol";

import { PushSplit } from "../../src/splitters/push/PushSplit.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { BaseTest } from "../Base.t.sol";

contract PushSplitTest is BaseTest {
    PushSplit private pushSplit;

    function setUp() public override {
        super.setUp();

        pushSplit = PushSplit(Clone.cloneDeterministic((address(new PushSplit(address(warehouse)))), 0));
    }

    function testFuzz_withdrawFromWarehouse(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        dealSplit(address(pushSplit), _token, 0, _amount);

        pushSplit.withdrawFromWarehouse(_token);

        assertEq(warehouse.balanceOf(address(pushSplit), tokenToId(_token)), 1);
        if (_native) assertEq(address(pushSplit).balance, _amount - 1);
        else assertEq(IERC20(_token).balanceOf(address(pushSplit)), _amount - 1);
    }

    function test_withdrawFromWarehouse_Revert_whenInvalidToken() public {
        vm.expectRevert();
        pushSplit.withdrawFromWarehouse(address(0));
    }
}
