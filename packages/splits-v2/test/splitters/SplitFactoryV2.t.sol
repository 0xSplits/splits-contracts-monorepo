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
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive);
        address predictedAddress = predictDeterministicAddress(params, _owner, _salt, _distributeByPush);

        vm.expectEmit();
        emit SplitCreated(predictedAddress, params, _owner, _creator);
        SplitWalletV2 split =
            SplitWalletV2(createSplitDeterministic(params, _owner, _creator, _salt, _distributeByPush));

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

        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive);

        vm.expectRevert();
        createSplitDeterministic(params, _owner, _creator, _salt, _distributeByPush);
    }

    function testFuzz_createSplitWithoutSalt(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator
    )
        public
    {
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive);

        address predictedAddress = predictDeterministicAddress(params, _owner, _distributeByPush);

        SplitWalletV2 split = SplitWalletV2(createSplit(params, _owner, _creator, _distributeByPush));

        assertEq(split.owner(), _owner);
        assertEq(address(split), predictedAddress);
    }

    function testFuzz_createSplitWithoutSalt_sameParams(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator
    )
        public
    {
        testFuzz_createSplitWithoutSalt(_receivers, _distributionIncentive, _distributeByPush, _owner, _creator);

        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive);
        address predictedAddress = predictDeterministicAddress(params, _owner, _distributeByPush);

        SplitWalletV2 split = SplitWalletV2(createSplit(params, _owner, _owner, _distributeByPush));

        assertEq(split.owner(), _owner);
        assertEq(address(split), predictedAddress);
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
        SplitV2Lib.Split memory params = createSplitParams(_receivers, _distributionIncentive);

        (address predictedAddress, bool isDeployed_) = isDeployed(params, _owner, _salt, _distributeByPush);

        assertEq(isDeployed_, false);

        testFuzz_create2Split(_receivers, _distributionIncentive, _distributeByPush, _owner, _creator, _salt);

        (predictedAddress, isDeployed_) = isDeployed(params, _owner, _salt, _distributeByPush);

        assertEq(isDeployed_, true);
    }

    function predictDeterministicAddress(
        SplitV2Lib.Split memory params,
        address _owner,
        bytes32 _salt,
        bool _push
    )
        private
        view
        returns (address)
    {
        if (_push) {
            return pushFactory.predictDeterministicAddress(params, _owner, _salt);
        } else {
            return pullFactory.predictDeterministicAddress(params, _owner, _salt);
        }
    }

    function predictDeterministicAddress(
        SplitV2Lib.Split memory params,
        address _owner,
        bool _push
    )
        private
        view
        returns (address)
    {
        if (_push) {
            return pushFactory.predictDeterministicAddress(params, _owner);
        } else {
            return pullFactory.predictDeterministicAddress(params, _owner);
        }
    }

    function createSplit(
        SplitV2Lib.Split memory params,
        address _owner,
        address _creator,
        bool _push
    )
        private
        returns (address)
    {
        if (_push) {
            return pushFactory.createSplit(params, _owner, _creator);
        } else {
            return pullFactory.createSplit(params, _owner, _creator);
        }
    }

    function createSplitDeterministic(
        SplitV2Lib.Split memory params,
        address _owner,
        address _creator,
        bytes32 _salt,
        bool _push
    )
        private
        returns (address)
    {
        if (_push) {
            return pushFactory.createSplitDeterministic(params, _owner, _creator, _salt);
        } else {
            return pullFactory.createSplitDeterministic(params, _owner, _creator, _salt);
        }
    }

    function isDeployed(
        SplitV2Lib.Split memory params,
        address _owner,
        bytes32 _salt,
        bool _push
    )
        private
        view
        returns (address, bool)
    {
        if (_push) {
            return pushFactory.isDeployed(params, _owner, _salt);
        } else {
            return pullFactory.isDeployed(params, _owner, _salt);
        }
    }
}
