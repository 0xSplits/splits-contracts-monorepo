// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { Clone } from "../../src/libraries/Clone.sol";
import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";
import { SplitWalletV2 } from "../../src/splitters/SplitWalletV2.sol";
import { Ownable } from "../../src/utils/Ownable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { Pausable } from "../../src/utils/Pausable.sol";
import { BaseTest } from "../Base.t.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract SplitWalletV2Test is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;
    using Address for address;

    event SplitUpdated(SplitV2Lib.Split _split);
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

        wallet = SplitWalletV2(Clone.clone(address(new SplitWalletV2(address(warehouse)))));
    }

    /* -------------------------------------------------------------------------- */
    /*                                 INITIALIZE                                 */
    /* -------------------------------------------------------------------------- */

    function testFuzz_initialize(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        wallet.initialize(split, _owner);

        assertEq(wallet.owner(), _owner);
        assertEq(address(wallet.SPLITS_WAREHOUSE()), address(warehouse));
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
        bool _distributeByPush,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

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
        bool _distributeByPush,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _distributionIncentive, _distributeByPush, _owner);

        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        vm.expectEmit();
        emit SplitUpdated(split);
        vm.prank(_owner);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_Unauthorized(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner
    )
        public
    {
        vm.assume(_receivers.length > 1);
        testFuzz_initialize(_receivers, _distributionIncentive, _distributeByPush, _owner);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        address[] memory receivers = new address[](split.recipients.length - 1);
        split.recipients = receivers;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner
    )
        public
    {
        testFuzz_initialize(_receivers, _distributionIncentive, _distributeByPush, _owner);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        split.totalAllocation = split.totalAllocation + 1;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_TotalAllocationMismatch.selector);
        wallet.updateSplit(split);
    }

    /* -------------------------------------------------------------------------- */
    /*                            DISTRIBUTE FUNCTIONS                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_distribute_Revert_whenPaused(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _useSimpleDistribute
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.setPaused(true);

        vm.expectRevert(Pausable.Paused.selector);
        if (_useSimpleDistribute) {
            wallet.distribute(split, address(usdc), ALICE.addr);
        } else {
            wallet.distribute(split, address(usdc), 0, 0, ALICE.addr);
        }
    }

    function testFuzz_distribute_Revert_whenInvalidSplit(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _useSimpleDistribute
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
        wallet.initialize(split, ALICE.addr);

        if (_distributionIncentive == type(uint16).max) {
            split.distributionIncentive -= 1;
        } else {
            split.distributionIncentive += 1;
        }

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        if (_useSimpleDistribute) {
            wallet.distribute(split, address(usdc), ALICE.addr);
        } else {
            wallet.distribute(split, address(usdc), 0, 0, ALICE.addr);
        }
    }

    function testFuzz_distribute_whenPaused_byOwner(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _native,
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _useSimpleDistribute
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
        address token;
        if (_native) token = native;
        else token = address(usdc);

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        vm.startPrank(ALICE.addr);
        wallet.setPaused(true);
        if (split.totalAllocation == 0 && split.recipients.length > 0) return;
        if (_useSimpleDistribute) {
            wallet.distribute(split, token, ALICE.addr);
        } else {
            uint256 totalAmount = uint256(_warehouseAmount) + uint256(_splitAmount);
            if (_distributeByPush) {
                if (_warehouseAmount > 0) {
                    totalAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _warehouseAmount, ALICE.addr);
            } else {
                if (_splitAmount > 0) {
                    totalAmount -= 1;
                    _splitAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _splitAmount, ALICE.addr);
            }
        }
        vm.stopPrank();

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr);
    }

    function testFuzz_distribute(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _native,
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _useSimpleDistribute
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
        address token;
        if (_native) token = native;
        else token = address(usdc);

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        if (split.totalAllocation == 0 && split.recipients.length > 0) vm.expectRevert();
        if (_useSimpleDistribute) {
            wallet.distribute(split, token, ALICE.addr);
        } else {
            uint256 totalAmount = uint256(_warehouseAmount) + uint256(_splitAmount);
            if (_distributeByPush) {
                if (_warehouseAmount > 0) {
                    totalAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _warehouseAmount, ALICE.addr);
            } else {
                if (_splitAmount > 0) {
                    totalAmount -= 1;
                    _splitAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _splitAmount, ALICE.addr);
            }
        }

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr);
    }

    function testFuzz_distribute_NativeByPush_whenRecipientReverts(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        bool _useSimpleDistribute
    )
        public
    {
        vm.assume(_receivers.length > 1);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive, true);
        split.recipients[0] = BAD_ACTOR;
        split.distributeByPush = true;

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), native, _splitAmount, _warehouseAmount);

        if (split.totalAllocation == 0 && split.recipients.length > 0) return;
        if (_useSimpleDistribute) {
            wallet.distribute(split, native, ALICE.addr);
        } else {
            uint256 totalAmount = uint256(_warehouseAmount) + uint256(_splitAmount);
            if (_warehouseAmount > 0) {
                totalAmount -= 1;
            }
            wallet.distribute(split, native, totalAmount, _warehouseAmount, ALICE.addr);
        }
        assertDistribute(split, native, _warehouseAmount, _splitAmount, ALICE.addr);
    }

    function testFuzz_wallet_receiveEthEvent(uint256 _amount) public {
        deal(address(this), _amount);
        vm.expectEmit();
        emit ReceiveETH(_amount);
        Address.sendValue(payable(address(wallet)), _amount);
    }

    function testFuzz_withdrawFromWarehouse(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        dealSplit(address(wallet), _token, 0, _amount);

        wallet.withdrawFromWarehouse(_token);

        assertEq(warehouse.balanceOf(address(wallet), tokenToId(_token)), 1);
        if (_native) assertEq(address(wallet).balance, _amount - 1);
        else assertEq(IERC20(_token).balanceOf(address(wallet)), _amount - 1);
    }

    function test_withdrawFromWarehouse_Revert_whenInvalidToken() public {
        vm.expectRevert();
        wallet.withdrawFromWarehouse(address(0));
    }

    function testFuzz_depositToWarehouse(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        if (_native) deal(address(wallet), _amount);
        else deal(_token, address(wallet), _amount);

        wallet.depositToWarehouse(_token, _amount);

        assertGte(warehouse.balanceOf(address(wallet), tokenToId(_token)), _amount);
        if (_native) assertEq(address(wallet).balance, 0);
        else assertEq(IERC20(_token).balanceOf(address(wallet)), 0);
    }

    function testFuzz_depositToWarehouse_whenApproved(bool _native, uint96 _amount1, uint96 _amount2) public {
        testFuzz_depositToWarehouse(_native, _amount1);
        testFuzz_depositToWarehouse(_native, _amount2);
    }

    function test_depositToWarehouse_Revert_whenInvalidToken() public {
        vm.expectRevert();
        wallet.depositToWarehouse(address(0), 0);
    }

    function testFuzz_depositToWarehouse_Revert_whenInvalidAmount(bool _native, uint256 _amount) public {
        vm.assume(_amount > 0);
        address _token = _native ? native : address(usdc);
        dealSplit(address(wallet), _token, _amount - 1, 0);

        vm.expectRevert();
        wallet.depositToWarehouse(_token, _amount);
    }

    function testFuzz_getSplitsBalance(bool _native) public {
        address _token = _native ? native : address(usdc);

        dealSplit(address(wallet), _token, 100, 100);

        (uint256 splitBalance, uint256 warehouseBalance) = wallet.getSplitBalance(_token);

        assertEq(splitBalance, 100);
        assertEq(warehouseBalance, 100);
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

    // solhint-disable-next-line code-complexity
    function assertDistribute(
        SplitV2Lib.Split memory _split,
        address _token,
        uint256 _warehouseAmount,
        uint256 _splitAmount,
        address _distributor
    )
        internal
    {
        uint256 totalAmount = _warehouseAmount + _splitAmount;
        if (_warehouseAmount > 0 && _split.distributeByPush == true) totalAmount -= 1;
        if (_splitAmount > 0 && _split.distributeByPush == false) totalAmount -= 1;
        (uint256[] memory amounts, uint256 reward) = SplitV2Lib.getDistributionsMem(_split, totalAmount);

        if (_split.distributeByPush) {
            if (_token == native) {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    uint256 balance = address(_split.recipients[i]).balance
                        + warehouse.balanceOf(_split.recipients[i], tokenToId(_token));
                    assertGte(balance, amounts[i]);
                }
                if (reward > 0) {
                    assertGte(_distributor.balance, reward);
                }
            } else {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    assertGte(IERC20(_token).balanceOf(_split.recipients[i]), amounts[i]);
                }
                if (reward > 0) {
                    assertGte(IERC20(_token).balanceOf(_distributor), reward);
                }
            }
        } else {
            for (uint256 i = 0; i < _split.recipients.length; i++) {
                assertGte(warehouse.balanceOf(_split.recipients[i], tokenToId(_token)), amounts[i]);
            }
            assertGte(warehouse.balanceOf(_distributor, tokenToId(_token)), reward);
        }
    }
}
