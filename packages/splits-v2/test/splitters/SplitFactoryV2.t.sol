// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitV2Lib } from "../../src/libraries/SplitV2.sol";
import { SplitWalletV2 } from "../../src/splitters/SplitWalletV2.sol";

import { BaseTest } from "../Base.t.sol";

contract SplitFactoryV2Test is BaseTest {
    event SplitCreated(address indexed split, SplitV2Lib.Split splitParams, address owner, address creator);

    function setUp() public override {
        super.setUp();
    }

    function testFuzz_create2Split(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator,
        bytes32 _salt
    )
        public
    {
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);
        address predictedAddress = splitFactory.predictDeterministicAddress(params, _owner, _salt);

        vm.expectEmit();
        emit SplitCreated(predictedAddress, params, _owner, _creator);
        SplitWalletV2 split = SplitWalletV2(splitFactory.createSplitDeterministic(params, _owner, _creator, _salt));

        assertEq(predictedAddress, address(split));
        assertEq(split.owner(), _owner);
    }

    function testFuzz_create2Split_Revert_SplitAlreadyExists(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator,
        bytes32 _salt
    )
        public
    {
        testFuzz_create2Split(_receivers, _distributionIncentive, _distributeByPush, _owner, _creator, _salt);

        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        vm.expectRevert();
        splitFactory.createSplitDeterministic(params, _owner, _creator, _salt);
    }

    function testFuzz_createSplit(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator
    )
        public
    {
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        SplitWalletV2 split = SplitWalletV2(splitFactory.createSplit(params, _owner, _creator));

        assertEq(split.owner(), _owner);
    }

    function testFuzz_createSplit_sameParams(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator
    )
        public
    {
        testFuzz_createSplit(_receivers, _distributionIncentive, _distributeByPush, _owner, _creator);

        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        SplitWalletV2 split = SplitWalletV2(splitFactory.createSplit(params, _owner, _owner));

        assertEq(split.owner(), _owner);
    }

    function testFuzz_isDeployed(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator,
        bytes32 _salt
    )
        public
    {
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive, _distributeByPush);

        (address predictedAddress, bool isDeployed) = splitFactory.isDeployed(params, _owner, _salt);

        assertEq(isDeployed, false);

        testFuzz_create2Split(_receivers, _distributionIncentive, _distributeByPush, _owner, _creator, _salt);

        (predictedAddress, isDeployed) = splitFactory.isDeployed(params, _owner, _salt);

        assertEq(isDeployed, true);
    }
}
