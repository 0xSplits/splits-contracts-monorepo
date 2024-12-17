// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../../src/libraries/Clone.sol";
import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";

import { PullSplit } from "../../src/splitters/pull/PullSplit.sol";

import { PullSplitFactory } from "../../src/splitters/pull/PullSplitFactory.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { BaseTest } from "../Base.t.sol";

contract PullSplitTest is BaseTest {
    PullSplit private pullSplit;

    string MAINNET_RPC_URL = vm.envString("MAINNET_RPC_URL");

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

    function test_distribute_USDT_Mainnet() public {
        // create new mainnet fork
        uint256 mainnetFork = vm.createFork(MAINNET_RPC_URL, 21_395_163);
        vm.selectFork(mainnetFork);

        // replicate v2.0 split on mainnet failing to distribute usdt
        address[] memory recipients = new address[](2);
        recipients[0] = 0xa7128c450131A6a39751D1B0E2aA44f21B55Ea73;
        recipients[1] = 0xAe4B8c350BB31ce40eaf75F154a2d354450cBe0f;

        uint256[] memory allocations = new uint256[](2);
        allocations[0] = 500_000;
        allocations[1] = 500_000;

        SplitV2Lib.Split memory split = SplitV2Lib.Split(recipients, allocations, 1_000_000, 0);

        address owner = 0x0F17233C18aEB1278C6814b979a37031d123cFB8;
        address splitAddress = 0xb051D24BDa0CB26877A982870E7B02Fb426c1963;
        address token = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
        address oldWarehouse = 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8;

        // deploy v2.1 split on mainnet
        pullFactory = new PullSplitFactory(oldWarehouse);

        // deploy new split
        address newSplit = pullFactory.createSplit(split, owner, owner);

        // try to distribute v2.0 split which should revert
        vm.expectRevert();
        PullSplit(splitAddress).distribute(split, token, owner);

        vm.startPrank(splitAddress);
        // transfer usdt to new split
        SafeERC20.safeTransfer(IERC20(token), newSplit, IERC20(token).balanceOf(splitAddress));
        vm.stopPrank();

        // distribute usdt
        PullSplit(newSplit).distribute(split, token, owner);

        assertEq(IERC20(token).balanceOf(newSplit), 1);
    }
}
