// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";
import { SplitFactoryV2 } from "../../src/splitters/SplitFactoryV2.sol";
import { SplitWalletV2 } from "../../src/splitters/SplitWalletV2.sol";
import { Ownable } from "../../src/utils/Ownable.sol";

import { Pausable } from "../../src/utils/Pausable.sol";
import { BaseTest } from "../Base.t.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract SplitWalletV2Test is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;
    using Address for address;

    event SplitUpdated(address indexed _owner, SplitV2Lib.Split _split);
    event SplitDistributionsPaused(bool _paused);
    event SplitDistributeByPush(bool _distributeByPush);
    event SplitDistributed(address indexed _token, uint256 _amount, address _distributor);
    event ReceiveETH(uint256);

    SplitWalletV2 private walletWithIncentive;
    SplitWalletV2 private walletWithNoIncentive;

    SplitWalletV2 private wallet;

    function setUp() public override {
        super.setUp();

        SplitV2Lib.Split memory splitWithIncentive = getDefaultSplitWithIncentive();
        SplitFactoryV2.CreateSplitParams memory _createSplitParams =
            SplitFactoryV2.CreateSplitParams(splitWithIncentive, ALICE.addr, address(0));
        walletWithIncentive = SplitWalletV2(splitFactory.createSplit(_createSplitParams));

        SplitV2Lib.Split memory splitWithNoIncentive = getDefaultSplitWithNoIncentive();
        _createSplitParams = SplitFactoryV2.CreateSplitParams(splitWithNoIncentive, ALICE.addr, address(0));
        walletWithNoIncentive = SplitWalletV2(splitFactory.createSplit(_createSplitParams));

        wallet = new SplitWalletV2(address(warehouse));
    }

    /* -------------------------------------------------------------------------- */
    /*                                 INITIALIZE                                 */
    /* -------------------------------------------------------------------------- */

    function testFuzz_initialize(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        vm.expectEmit();
        emit SplitUpdated(_owner, split);
        wallet.initialize(split, _owner);

        assertEq(wallet.owner(), _owner);
        assertEq(address(wallet.SPLITS_WAREHOUSE()), address(warehouse));
        assertEq(wallet.distributeByPush(), false);
        assertEq(wallet.splitHash(), split.getHashMem());
    }

    function testFuzz_initialize_Revert_whenNotFactory(SplitV2Lib.Split memory _split, address _owner) public {
        vm.prank(address(0));
        vm.expectRevert(SplitWalletV2.UnauthorizedInitializer.selector);
        wallet.initialize(_split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        split.totalAllocation = split.totalAllocation + 1;

        vm.expectRevert(SplitV2Lib.InvalidSplit_TotalAllocationMismatch.selector);
        wallet.initialize(split, _owner);
    }

    /* -------------------------------------------------------------------------- */
    /*                               OWNER FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    function testFuzz_updateSplit(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _distributionIncentive, _owner);

        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        vm.expectEmit();
        emit SplitUpdated(_owner, split);
        vm.prank(_owner);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_Unauthorized(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive
    )
        public
    {
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        testFuzz_initialize(_receivers, _distributionIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _distributionIncentive, _owner);
        SplitV2Lib.Split memory split = createSplit(_receivers, _distributionIncentive);

        split.totalAllocation = split.totalAllocation + 1;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_TotalAllocationMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateDistributeByPush(bool _distributeByPush) public {
        vm.expectEmit();
        emit SplitDistributeByPush(_distributeByPush);
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

    function testFuzz_distribute_Revert_whenPaused(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.setPaused(true);

        vm.expectRevert(Pausable.Paused.selector);
        wallet.distribute(split, address(usdc), _amount, ALICE.addr);
    }

    function testFuzz_distribute_Revert_whenInvalidSplit(uint256 _amount) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        split.distributionIncentive += 1;

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        wallet.distribute(split, address(usdc), _amount, ALICE.addr);
    }

    function testFuzz_distributeERC20_Revert_whenInvalidToken(uint256 _amount) public {
        vm.assume(_amount > 10);
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.expectRevert();
        wallet.distribute(split, native, _amount, ALICE.addr);
    }

    function testFuzz_distributeERC20_NoIncentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(usdc), address(wallet), _amount);

        wallet.approveSplitsWarehouse(address(usdc));

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        wallet.distribute(split, address(usdc), _amount, ALICE.addr);

        assertAlmostEq(usdc.balanceOf(address(wallet)), 0, 9);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(usdc.balanceOf(split.recipients[i]), 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(address(usdc))), 0);
            }
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

        wallet.approveSplitsWarehouse(address(usdc));
        wallet.distribute(split, address(usdc), _amount, ALICE.addr);

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
        }
    }

    function testFuzz_distributeNative_NoIncentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        wallet.distribute(split, native, _amount, ALICE.addr);

        assertAlmostEq(address(wallet).balance, 0, 9);

        if (_distributeByPush) {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(split.recipients[i].balance, 0);
            }
        } else {
            for (uint256 i = 0; i < split.recipients.length; i++) {
                assertGt(warehouse.balanceOf(split.recipients[i], tokenToId(native)), 0);
            }
        }
    }

    function testFuzz_distribute_Incentive(uint256 _amount, bool _distributeByPush) public {
        SplitV2Lib.Split memory split = getDefaultSplitWithIncentive();

        wallet.initialize(split, ALICE.addr);

        _amount = bound(_amount, split.totalAllocation, type(uint160).max);

        deal(address(wallet), _amount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeByPush(_distributeByPush);

        uint256 distributorBalance = ALICE.addr.balance;

        wallet.distribute(split, native, _amount, ALICE.addr);

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
        }
    }

    function test_approveSplitsWarehouse() public {
        wallet.approveSplitsWarehouse(address(usdc));

        assertEq(usdc.allowance(address(wallet), address(warehouse)), type(uint256).max);
    }

    function test_approveSplitsWarehouse_revert_whenNonERC20() public {
        vm.expectRevert();
        wallet.approveSplitsWarehouse(native);
    }

    function testFuzz_wallet_receiveEthEvent(uint256 _amount) public {
        deal(address(this), _amount);
        vm.expectEmit();
        emit ReceiveETH(_amount);
        Address.sendValue(payable(address(walletWithIncentive)), _amount);
    }

    function getDefaultSplitWithNoIncentive() internal pure returns (SplitV2Lib.Split memory) {
        SplitReceiver[] memory receivers = new SplitReceiver[](10);
        for (uint256 i = 100; i < 100 + receivers.length; i++) {
            receivers[i - 100] = SplitReceiver(address(uint160(i + 1)), uint32(10));
        }

        return createSplit(receivers, 0);
    }

    function getDefaultSplitWithIncentive() internal pure returns (SplitV2Lib.Split memory) {
        SplitReceiver[] memory receivers = new SplitReceiver[](10);
        for (uint256 i = 100; i < 100 + receivers.length; i++) {
            receivers[i - 100] = SplitReceiver(address(uint160(i + 1)), uint32(10));
        }

        return createSplit(receivers, uint16(1e4));
    }
}
