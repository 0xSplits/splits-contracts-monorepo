// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../../../src/libraries/Clone.sol";
import { SplitV2Lib } from "../../../src/libraries/SplitV2.sol";

import { PullSplit, SplitWalletV2 } from "../../../src/splitters/pull/PullSplit.sol";
import { PushSplit } from "../../../src/splitters/push/PushSplit.sol";
import { Ownable } from "../../../src/utils/Ownable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { Pausable } from "../../../src/utils/Pausable.sol";
import { BaseTest } from "../../Base.t.sol";
import { ApprovalRaceToken } from "../../mocks/ApprovalRace.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract ApprovalRaceTest is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;
    using Address for address;

    SplitWalletV2 private pullSplit;
    SplitWalletV2 private pushSplit;
    SplitWalletV2 private wallet;

    ApprovalRaceToken private customToken;

    address private token;

    function setUp() public override {
        super.setUp();

        pullSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PullSplit(address(warehouse)))), 0));
        pushSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PushSplit(address(warehouse)))), 0));

        customToken = new ApprovalRaceToken(0);
        token = address(customToken);
    }

    /* -------------------------------------------------------------------------- */
    /*                            DISTRIBUTE FUNCTIONS                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_distribute(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        uint96 _splitAmount,
        uint96 _warehouseAmount
    )
        public
    {
        SplitV2Lib.Split memory split = createSplitParams(_receivers, _distributionIncentive);

        wallet = _distributeByPush ? pushSplit : pullSplit;

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, _warehouseAmount);

        if (split.totalAllocation == 0 && split.recipients.length > 0) return;

        wallet.distribute(split, token, ALICE.addr);

        assertDistribute(split, token, _warehouseAmount, _splitAmount, ALICE.addr, _distributeByPush);

        if (!_distributeByPush) {
            uint256 numRecipients = split.recipients.length;

            for (uint256 i = 0; i < numRecipients; i++) {
                if (warehouse.balanceOf(split.recipients[i], tokenToId(token)) > 0) {
                    warehouse.withdraw(split.recipients[i], token);
                }
            }
        }
    }

    function testFuzz_double_distribute_pull_split_approve_race() public {
        uint256 _splitAmount = type(uint256).max - 1;

        SplitReceiver[] memory _receivers = new SplitReceiver[](1);

        _receivers[0] = SplitReceiver({ receiver: ALICE.addr, allocation: 1 });

        SplitV2Lib.Split memory split = createSplitParams(_receivers, 0);

        wallet = pullSplit;

        wallet.initialize(split, ALICE.addr);

        // First distribute
        dealSplit(address(wallet), token, _splitAmount, 0);

        if (split.totalAllocation == 0 && split.recipients.length > 0) return;

        wallet.distribute(split, token, ALICE.addr);

        assertDistribute(split, token, 0, _splitAmount, ALICE.addr, false);

        uint256 numRecipients = split.recipients.length;

        for (uint256 i = 0; i < numRecipients; i++) {
            if (warehouse.balanceOf(split.recipients[i], tokenToId(token)) > 0) {
                warehouse.withdraw(split.recipients[i], token);
            }
        }

        // Second distribute
        _receivers[0] = SplitReceiver({ receiver: BOB.addr, allocation: 1 });

        split = createSplitParams(_receivers, 0);

        wallet.initialize(split, ALICE.addr);

        dealSplit(address(wallet), token, _splitAmount, 0);

        if (split.totalAllocation == 0 && split.recipients.length > 0) return;

        wallet.distribute(split, token, ALICE.addr);
    }
}
