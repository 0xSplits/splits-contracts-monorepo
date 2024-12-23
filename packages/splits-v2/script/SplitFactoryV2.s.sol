// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { PullSplitFactory } from "../src/splitters/pull/PullSplitFactory.sol";
import { PushSplitFactory } from "../src/splitters/push/PushSplitFactory.sol";

import { BaseScript } from "./Base.s.sol";

contract SplitFactoryV2Script is BaseScript {
    function run() public {
        address warehouse = getAddressFromConfig("splitsWarehouse");

        vm.startBroadcast();
        address pull_factory =
            address(new PullSplitFactory{ salt: keccak256("splits.pullSplitFactory.v2.1") }(warehouse));
        address push_factory =
            address(new PushSplitFactory{ salt: keccak256("splits.pushSplitFactory.v2.1") }(warehouse));
        vm.stopBroadcast();

        updateDeployment(pull_factory, "PullSplitFactoryV2.1");
        updateDeployment(push_factory, "PushSplitFactoryV2.1");
    }
}
