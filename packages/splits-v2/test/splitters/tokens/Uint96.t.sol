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
import { Uint96ERC20 } from "../../mocks/Uint96.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

contract Uint96Test is BaseTest {
    using SplitV2Lib for SplitV2Lib.Split;
    using Address for address;

    event SplitDistributed(address indexed _token, uint256 _amount, address _distributor);

    SplitWalletV2 private pullSplit;
    SplitWalletV2 private pushSplit;
    SplitWalletV2 private wallet;

    Uint96ERC20 private customToken;

    address private token;

    function setUp() public override {
        super.setUp();

        pullSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PullSplit(address(warehouse)))), 0));
        pushSplit = SplitWalletV2(Clone.cloneDeterministic((address(new PushSplit(address(warehouse)))), 0));

        customToken = new Uint96ERC20(0);
        token = address(customToken);
    }

    /* -------------------------------------------------------------------------- */
    /*                            DISTRIBUTE FUNCTIONS                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_distribute(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        uint48 _splitAmount,
        uint48 _warehouseAmount
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
}
