// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";
import { SplitWalletV2 } from "../../src/splitters/SplitWalletV2.sol";
import { Ownable } from "../../src/utils/Ownable.sol";
import { BaseTest } from "../Base.t.sol";

contract SplitWalletV2Test is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;

    SplitWalletV2 private wallet;

    function setUp() public override {
        super.setUp();

        wallet = new SplitWalletV2(address(warehouse), address(this));
    }

    /* -------------------------------------------------------------------------- */
    /*                                 INITIALIZE                                 */
    /* -------------------------------------------------------------------------- */

    function testFuzz_initialize(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        vm.expectEmit();
        emit SplitWalletV2.SplitUpdated(_owner, split);
        wallet.initialize(split, _owner);

        assertEq(wallet.owner(), _owner);
        assertEq(address(wallet.SPLIT_WAREHOUSE()), address(warehouse));
        assertEq(wallet.distributeByPush(), false);
        assertEq(wallet.distributionsPaused(), false);
        assertEq(wallet.splitHash(), split.getHashMem());
    }

    function testFuzz_initialize_Revert_whenNotFactory(SplitV2Lib.Split memory _split, address _owner) public {
        vm.prank(address(0));
        vm.expectRevert(SplitWalletV2.UnauthorizedInitializer.selector);
        wallet.initialize(_split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.totalAllocation = split.totalAllocation + 1;

        vm.expectRevert(SplitV2Lib.InvalidSplit_TotalAllocationMismatch.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_InvalidIncentivePush(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.pushDistributionIncentive = SplitV2Lib.calculateMaxIncentive(split.totalAllocation) + 1;

        vm.expectRevert(SplitV2Lib.InvalidSplit_InvalidIncentive.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_InvalidIncentivePull(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.pullDistributionIncentive = SplitV2Lib.calculateMaxIncentive(split.totalAllocation) + 1;

        vm.expectRevert(SplitV2Lib.InvalidSplit_InvalidIncentive.selector);
        wallet.initialize(split, _owner);
    }

    /* -------------------------------------------------------------------------- */
    /*                               OWNER FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    function testFuzz_updateSplit(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _pullIncentive, _pushIncentive, _owner);

        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        vm.expectEmit();
        emit SplitWalletV2.SplitUpdated(_owner, split);
        vm.prank(_owner);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_Unauthorized(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        testFuzz_initialize(_receivers, _pullIncentive, _pushIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _pullIncentive, _pushIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.totalAllocation = split.totalAllocation + 1;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_TotalAllocationMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_InvalidIncentivePush(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _pullIncentive, _pushIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.pushDistributionIncentive = SplitV2Lib.calculateMaxIncentive(split.totalAllocation) + 1;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_InvalidIncentive.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_InvalidIncentivePull(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _pullIncentive, _pushIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _pullIncentive, _pushIncentive);

        split.pullDistributionIncentive = SplitV2Lib.calculateMaxIncentive(split.totalAllocation) + 1;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_InvalidIncentive.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_pauseDistributions(bool _pause) public {
        vm.expectEmit();
        emit SplitWalletV2.SplitDistributionsPaused(_pause);
        vm.prank(wallet.owner());
        wallet.pauseDistributions(_pause);
    }

    function testFuzz_pauseDistributions_Revert_Unauthorized(bool _pause) public {
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.pauseDistributions(_pause);
    }

    function testFuzz_updateDistributeByPush(bool _distributeByPush) public {
        vm.expectEmit();
        emit SplitWalletV2.SplitDistributeByPush(_distributeByPush);
        vm.prank(wallet.owner());
        wallet.updateDistributeByPush(_distributeByPush);
    }

    function testFuzz_updateDistributeByPush_Revert_Unauthorized(bool _distributeByPush) public {
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateDistributeByPush(_distributeByPush);
    }

    /* -------------------------------------------------------------------------- */
    /*                            DISTRIBUTE FUNCTIONS                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_distributeERC20_Revert_whenDistributionsPaused(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.pauseDistributions(true);

        vm.expectRevert(SplitWalletV2.DistributionsPaused.selector);
        wallet.distributeERC20(split, address(usdc), _amount, ALICE.addr);
    }

    function testFuzz_distributeNative_Revert_whenDistributionsPaused(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.pauseDistributions(true);

        vm.expectRevert(SplitWalletV2.DistributionsPaused.selector);
        wallet.distributeNative(split, _amount, ALICE.addr);
    }

    function testFuzz_distributeERC20_Revert_whenInvalidSplit(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        split.pullDistributionIncentive += 1;

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        wallet.distributeERC20(split, address(usdc), _amount, ALICE.addr);
    }

    function testFuzz_distributeNative_Revert_whenInvalidSplit(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        split.pullDistributionIncentive += 1;

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        wallet.distributeNative(split, _amount, ALICE.addr);
    }

    function testFuzz_distributeERC20_Revert_whenInvalidToken(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.expectRevert(SplitWalletV2.InvalidToken.selector);
        wallet.distributeERC20(split, native, _amount, ALICE.addr);
    }

    function testFuzz_distributeERC20_NoIncentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(usdc), address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        wallet.distributeERC20(split, address(usdc), _amount, ALICE.addr);

        assertAlmostEq(usdc.balanceOf(address(wallet)), 0, 9);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(usdc.balanceOf(split.recipients[i]), 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(address(usdc))), 0);
            }
            assertEq(warehouse.totalSupply(tokenToId(address(usdc))), usdc.balanceOf(address(warehouse)));
        }
    }

    function testFuzz_distributeERC20_Incentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(usdc), address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        uint256 distributorBalance = usdc.balanceOf(address(ALICE.addr));

        wallet.distributeERC20(split, address(usdc), _amount, ALICE.addr);

        assertAlmostEq(usdc.balanceOf(address(wallet)), 0, 9);
        assertGt(usdc.balanceOf(address(ALICE.addr)), distributorBalance);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(usdc.balanceOf(split.recipients[i]), 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(address(usdc))), 0);
            }
            assertEq(warehouse.totalSupply(tokenToId(address(usdc))), usdc.balanceOf(address(warehouse)));
        }
    }

    function testFuzz_distributeNative_NoIncentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        wallet.distributeNative(split, _amount, ALICE.addr);

        assertAlmostEq(address(wallet).balance, 0, 9);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(split.recipients[i].balance, 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(native)), 0);
            }
            assertEq(warehouse.totalSupply(tokenToId(address(native))), address(warehouse).balance);
        }
    }

    function testFuzz_distributeNative_Incentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        uint256 distributorBalance = ALICE.addr.balance;

        wallet.distributeNative(split, _amount, ALICE.addr);

        assertAlmostEq(address(wallet).balance, 0, 9);
        assertGt(ALICE.addr.balance, distributorBalance);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(split.recipients[i].balance, 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(native)), 0);
            }
            assertEq(warehouse.totalSupply(tokenToId(address(native))), address(warehouse).balance);
        }
    }

    function getDefaultSplitWithNoIncentive() internal pure returns (SplitV2Lib.Split memory) {
        SplitReceiver[] memory receivers = new SplitReceiver[](10);
        for (uint256 i = 100; i < 100 + receivers.length; i++) {
            receivers[i - 100] = SplitReceiver(address(uint160(i + 1)), uint32(10));
        }

        return createSplit(receivers, 0, 0);
    }

    function getDefaultSplitWithIncentive() internal pure returns (SplitV2Lib.Split memory) {
        SplitReceiver[] memory receivers = new SplitReceiver[](10);
        for (uint256 i = 100; i < 100 + receivers.length; i++) {
            receivers[i - 100] = SplitReceiver(address(uint160(i + 1)), uint32(10));
        }

        return createSplit(receivers, 10, 10);
    }
}
