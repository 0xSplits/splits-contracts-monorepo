// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { PullSplitFactory } from "../src/splitters/pull/PullSplitFactory.sol";
import { PushSplitFactory } from "../src/splitters/push/PushSplitFactory.sol";

import { BaseScript } from "./Base.s.sol";

contract SplitFactoryV2Script is BaseScript {
    function run() public {
        vm.createSelectFork("mainnet"); // 1
        deploy();

        vm.createSelectFork("optimism"); // 10
        deploy();

        vm.createSelectFork("bsc"); // 56
        deploy();

        vm.createSelectFork("gnosis"); // 100
        deploy();

        vm.createSelectFork("polygon"); // 137
        deploy();

        vm.createSelectFork("shape"); // 360
        deploy();

        vm.createSelectFork("world"); // 480
        deploy();

        vm.createSelectFork("world-sepolia"); // 4801
        deploy();

        vm.createSelectFork("base"); // 8453
        deploy();

        vm.createSelectFork("holesky"); // 17000
        deploy();

        vm.createSelectFork("arbitrum"); // 42161
        deploy();

        vm.createSelectFork("base-sepolia"); // 84532
        deploy();

        vm.createSelectFork("plume"); // 98866
        deploy();

        vm.createSelectFork("plume-sepolia"); // 98867
        deploy();

        vm.createSelectFork("arbitrum-sepolia"); // 421614
        deploy();

        vm.createSelectFork("hoodi"); // 560048
        deploy();

        vm.createSelectFork("zora"); // 7777777
        deploy();

        vm.createSelectFork("sepolia"); // 11155111
        deploy();

        vm.createSelectFork("optimism-sepolia"); // 11155420
        deploy();

        vm.createSelectFork("zora-sepolia"); // 9999999
        deploy();
    }

    function deploy() public {
        address warehouse = getAddressFromConfig("splitsWarehouse");

        vm.startBroadcast();
        address pull_factory =
            address(new PullSplitFactory{ salt: keccak256("splits.pullSplitFactory.v2.2") }(warehouse));
        address push_factory =
            address(new PushSplitFactory{ salt: keccak256("splits.pushSplitFactory.v2.2") }(warehouse));
        vm.stopBroadcast();

        updateDeployment(pull_factory, "PullSplitFactoryV2.2");
        updateDeployment(push_factory, "PushSplitFactoryV2.2");
    }
}
