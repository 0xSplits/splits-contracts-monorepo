// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../../src/libraries/Clone.sol";
import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";

import { PullSplit, SplitWalletV2 } from "../../src/splitters/pull/PullSplit.sol";
import { PushSplit } from "../../src/splitters/push/PushSplit.sol";
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

    SplitWalletV2 private pullSplit;
    SplitWalletV2 private pushSplit;
    SplitWalletV2 private wallet;

    function setUp() public override {
        super.setUp();

        pullSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PullSplit(address(warehouse)))), 0));
        pushSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PushSplit(address(warehouse)))), 0));
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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        wallet = _distributeByPush ? pushSplit : pullSplit;

        wallet.initialize(split, _owner);

        assertEq(wallet.owner(), _owner);
        assertEq(address(wallet.SPLITS_WAREHOUSE()), address(warehouse));
        assertEq(wallet.splitHash(), split.getHashMem());
    }

    function testFuzz_initialize_Revert_whenNotFactory(
        SplitV2Lib.Split memory _split,
        address _owner,
        address _sender,
        bool _distributeByPush
    )
        public
    {
        vm.assume(_sender != address(this));

        wallet = _distributeByPush ? pushSplit : pullSplit;

        vm.prank(_sender);
        vm.expectRevert(SplitWalletV2.UnauthorizedInitializer.selector);
        wallet.initialize(_split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        uint8 _length
    )
        public
    {
        vm.assume(_receivers.length > 1 && _length != _receivers.length);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        address[] memory receivers = new address[](_length);
        split.recipients = receivers;

        wallet = _distributeByPush ? pushSplit : pullSplit;

        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.initialize(split, _owner);
    }

    function testFuzz_initialize_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        uint256 _totalAllocation
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        vm.assume(_totalAllocation != split.totalAllocation);

        split.totalAllocation = _totalAllocation;

        wallet = _distributeByPush ? pushSplit : pullSplit;

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

        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        wallet = _distributeByPush ? pushSplit : pullSplit;

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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        wallet = _distributeByPush ? pushSplit : pullSplit;

        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_LengthMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        uint8 _length
    )
        public
    {
        vm.assume(_receivers.length > 1 && _length != _receivers.length);
        testFuzz_initialize(_receivers, _distributionIncentive, _distributeByPush, _owner);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        address[] memory receivers = new address[](_length);
        split.recipients = receivers;

        wallet = _distributeByPush ? pushSplit : pullSplit;

        vm.prank(_owner);
        vm.expectRevert(SplitV2Lib.InvalidSplit_LengthMismatch.selector);
        wallet.updateSplit(split);
    }

    function testFuzz_updateSplit_Revert_InvalidSplit_TotalAllocationMismatch(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        uint256 _totalAllocation
    )
        public
    {
        testFuzz_initialize(_receivers, _distributionIncentive, _distributeByPush, _owner);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        vm.assume(_totalAllocation != split.totalAllocation);

        split.totalAllocation = _totalAllocation;

        wallet = _distributeByPush ? pushSplit : pullSplit;

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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        wallet = _distributeByPush ? pushSplit : pullSplit;
        wallet.initialize(split, ALICE.addr);

        vm.prank(ALICE.addr);
        wallet.setPaused(true);

        vm.expectRevert(Pausable.Paused.selector);
        if (_useSimpleDistribute) {
            wallet.distribute(split, address(usdc), ALICE.addr);
        } else {
            wallet.distribute(split, address(usdc), 0, false, ALICE.addr);
        }
    }

    function testFuzz_distribute_Revert_whenInvalidSplit(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _useSimpleDistribute,
        SplitReceiver[] memory _receivers2,
        uint16 _distributionIncentiv2
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        wallet = _distributeByPush ? pushSplit : pullSplit;
        wallet.initialize(split, ALICE.addr);

        SplitV2Lib.Split memory split2 = createSplitParams(_receivers2, _distributionIncentiv2);

        vm.assume(split.getHashMem() != split2.getHashMem());

        vm.expectRevert(SplitWalletV2.InvalidSplit.selector);
        if (_useSimpleDistribute) {
            wallet.distribute(split2, address(usdc), ALICE.addr);
        } else {
            wallet.distribute(split2, address(usdc), 0, false, ALICE.addr);
        }
    }

    function testFuzz_distribute_Revert_whenAmountGreaterThanBalance(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        bool _native,
        uint96 _splitAmount,
        uint96 _warehouseAmount,
        uint256 _distributeAmount
    )
        public
    {
        vm.assume(_distributeAmount > uint256(_splitAmount) + _warehouseAmount && _distributeAmount > type(uint96).max);
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        address token;
        if (_native) token = native;
        else token = address(usdc);

        wallet = _distributeByPush ? pushSplit : pullSplit;

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        vm.assume(split.totalAllocation > 0);

        uint256 totalAmount = uint256(_warehouseAmount) + uint256(_splitAmount);
        if (_distributeByPush) {
            if (_warehouseAmount > 0) {
                totalAmount -= 1;
            }

            vm.expectRevert();
            wallet.distribute(split, token, _distributeAmount, _warehouseAmount > 1, ALICE.addr);
        } else {
            if (_splitAmount > 0) {
                totalAmount -= 1;
                _splitAmount -= 1;
            }

            vm.expectRevert();
            wallet.distribute(split, token, _distributeAmount, _splitAmount > 1, ALICE.addr);
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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        address token;
        if (_native) token = native;
        else token = address(usdc);

        wallet = _distributeByPush ? pushSplit : pullSplit;

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
                wallet.distribute(split, token, totalAmount, _warehouseAmount > 1, ALICE.addr);
            } else {
                if (_splitAmount > 0) {
                    totalAmount -= 1;
                    _splitAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _splitAmount > 1, ALICE.addr);
            }
        }
        vm.stopPrank();

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr, _distributeByPush);
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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        address token;
        if (_native) token = native;
        else token = address(usdc);

        wallet = _distributeByPush ? pushSplit : pullSplit;

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        if (split.totalAllocation == 0 && split.recipients.length > 0) return;
        if (_useSimpleDistribute) {
            wallet.distribute(split, token, ALICE.addr);
        } else {
            uint256 totalAmount = uint256(_warehouseAmount) + uint256(_splitAmount);
            if (_distributeByPush) {
                if (_warehouseAmount > 0) {
                    totalAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _warehouseAmount > 1, ALICE.addr);
            } else {
                if (_splitAmount > 0) {
                    totalAmount -= 1;
                    _splitAmount -= 1;
                }
                wallet.distribute(split, token, totalAmount, _splitAmount > 1, ALICE.addr);
            }
        }

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr, _distributeByPush);
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
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);
        split.recipients[0] = BAD_ACTOR;

        wallet = pushSplit;

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
            wallet.distribute(split, native, totalAmount, _warehouseAmount > 1, ALICE.addr);
        }
        assertDistribute(split, native, _warehouseAmount, _splitAmount, ALICE.addr, true);
    }

    function testFuzz_wallet_receiveEthEvent(uint256 _amount, bool _distributeByPush) public {
        wallet = _distributeByPush ? pushSplit : pullSplit;

        deal(address(this), _amount);
        vm.expectEmit();
        emit ReceiveETH(_amount);
        Address.sendValue(payable(address(wallet)), _amount);
    }

    function testFuzz_getSplitsBalance(bool _native, bool _push) public {
        address _token = _native ? native : address(usdc);

        wallet = _push ? pushSplit : pullSplit;

        dealSplit(address(wallet), _token, 100, 100);

        (uint256 splitBalance, uint256 warehouseBalance) = wallet.getSplitBalance(_token);

        assertEq(splitBalance, 100);
        assertEq(warehouseBalance, 100);
    }

    // solhint-disable-next-line code-complexity
    function assertDistribute(
        SplitV2Lib.Split memory _split,
        address _token,
        uint256 _warehouseAmount,
        uint256 _splitAmount,
        address _distributor,
        bool _distributeByPush
    )
        internal
    {
        if (_warehouseAmount > 0) _warehouseAmount -= 1;
        if (_splitAmount > 0) _splitAmount -= 1;

        uint256 totalAmount = _warehouseAmount + _splitAmount;

        (uint256[] memory amounts, uint256 reward) = SplitV2Lib.getDistributionsMem(_split, totalAmount);

        if (_distributeByPush) {
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
