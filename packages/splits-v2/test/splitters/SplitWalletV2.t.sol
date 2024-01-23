// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { Clone } from "../../src/libraries/Clone.sol";
import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";
import { SplitFactoryV2 } from "../../src/splitters/SplitFactoryV2.sol";
import { SplitWalletV2 } from "../../src/splitters/SplitWalletV2.sol";
import { Ownable } from "../../src/utils/Ownable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { Pausable } from "../../src/utils/Pausable.sol";
import { BaseTest } from "../Base.t.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract SplitWalletV2Test is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;
    using Address for address;

    event SplitUpdated(address indexed _owner, SplitV2Lib.Split _split);
    event SplitDistributionsPaused(bool _paused);
    event DistributeDirectionUpdated(bool _distributeByPush);
    event SplitDistributed(address indexed _token, uint256 _amount, address _distributor);
    event ReceiveETH(uint256);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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

        wallet = SplitWalletV2(Clone.clone(address(new SplitWalletV2(address(warehouse)))));
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
        emit DistributeDirectionUpdated(_distributeByPush);
        vm.prank(wallet.owner());
        wallet.updateDistributeDirection(_distributeByPush);
    }

    function testFuzz_updateDistributeByPush_Revert_Unauthorized(bool _distributeByPush) public {
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateDistributeDirection(_distributeByPush);
    }

    /* -------------------------------------------------------------------------- */
    /*                            DISTRIBUTE FUNCTIONS                            */
    /* -------------------------------------------------------------------------- */

    function test_distribute_Revert_whenPaused() public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.setPaused(true);

        vm.expectRevert(Pausable.Paused.selector);
        wallet.distribute(split, address(usdc), ALICE.addr);
    }

    function test_distribute_Revert_whenInvalidSplit() public {
        SplitV2Lib.Split memory split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        split.distributionIncentive += 1;

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        wallet.distribute(split, address(usdc), ALICE.addr);
    }

    function testFuzz_distribute_whenPaused_byOwner(
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _distributeByPush,
        bool _native,
        bool _incentive
    )
        public
    {
        address token;
        if (_native) token = native;
        else token = address(usdc);

        SplitV2Lib.Split memory split;
        if (_incentive) split = getDefaultSplitWithIncentive();
        else split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        vm.startPrank(ALICE.addr);
        wallet.updateDistributeDirection(_distributeByPush);
        wallet.setPaused(true);
        wallet.distribute(split, token, ALICE.addr);
        vm.stopPrank();

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr, _distributeByPush, type(uint256).max);
    }

    function testFuzz_distribute(
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _distributeByPush,
        bool _native,
        bool _incentive
    )
        public
    {
        address token;
        if (_native) token = native;
        else token = address(usdc);

        SplitV2Lib.Split memory split;
        if (_incentive) split = getDefaultSplitWithIncentive();
        else split = getDefaultSplitWithNoIncentive();

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeDirection(_distributeByPush);

        wallet.distribute(split, token, ALICE.addr);

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr, _distributeByPush, type(uint256).max);
    }

    function testFuzz_distribute_NativeByPush_whenRecipientReverts(
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _incentive
    )
        public
    {
        SplitV2Lib.Split memory split;
        if (_incentive) split = getDefaultSplitWithIncentive();
        else split = getDefaultSplitWithNoIncentive();

        split.recipients[0] = BAD_ACTOR;

        wallet.initialize(split, ALICE.addr);

        uint256 splitAmount = bound(_splitAmount, split.totalAllocation, type(uint160).max);

        dealSplit(address(wallet), native, splitAmount, _warehouseAmount);

        vm.prank(ALICE.addr);
        wallet.updateDistributeDirection(true);

        wallet.distribute(split, native, ALICE.addr);
        assertDistribute(split, native, _warehouseAmount, splitAmount, ALICE.addr, true, 0);
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

        return createSplit(receivers, uint16(1.1e4));
    }

    function dealSplit(address _split, address _token, uint256 _splitAmount, uint256 _warehouseAmount) internal {
        if (_token == native) deal(_split, _splitAmount);
        else deal(_token, _split, _splitAmount);

        address depositor = createUser("depositor").addr;
        if (_token == native) deal(depositor, _warehouseAmount);
        else deal(_token, depositor, _warehouseAmount);

        vm.startPrank(depositor);

        if (_token == native) {
            warehouse.deposit{ value: _warehouseAmount }(_split, _token, _warehouseAmount);
        } else {
            IERC20(_token).approve(address(warehouse), _warehouseAmount);
            warehouse.deposit(_split, _token, _warehouseAmount);
        }
        vm.stopPrank();
    }

    function assertDistribute(
        SplitV2Lib.Split memory _split,
        address _token,
        uint256 _warehouseAmount,
        uint256 _splitAmount,
        address _distributor,
        bool _distributeByPush,
        uint256 _badRecipient
    )
        internal
    {
        uint256 totalAmount = _warehouseAmount + _splitAmount;
        if (_warehouseAmount > 0 && _distributeByPush == true) totalAmount -= 1;
        if (_splitAmount > 0 && _distributeByPush == false) totalAmount -= 1;
        (uint256[] memory amounts,, uint256 reward) = SplitV2Lib.getDistributionsMem(_split, totalAmount);

        if (_distributeByPush) {
            if (_token == native) {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    if (i == _badRecipient) {
                        assertEq(_split.recipients[i].balance, 0);
                        assertEq(warehouse.balanceOf(_split.recipients[i], tokenToId(_token)), amounts[i]);
                    } else {
                        assertEq(_split.recipients[i].balance, amounts[i]);
                    }
                }
                if (reward > 0) {
                    assertEq(_distributor.balance, reward);
                }
            } else {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    assertEq(IERC20(_token).balanceOf(_split.recipients[i]), amounts[i]);
                }
                if (reward > 0) {
                    assertEq(IERC20(_token).balanceOf(_distributor), reward);
                }
            }
        } else {
            for (uint256 i = 0; i < _split.recipients.length; i++) {
                assertEq(warehouse.balanceOf(_split.recipients[i], tokenToId(_token)), amounts[i]);
            }
            assertEq(warehouse.balanceOf(_distributor, tokenToId(_token)), reward);
        }
    }
}
