// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { PullSplitFactory } from "../src/splitters/pull/PullSplitFactory.sol";
import { PushSplitFactory } from "../src/splitters/push/PushSplitFactory.sol";

import { BaseScript } from "./Base.s.sol";

contract SplitFactoryV2Script is BaseScript {
    uint88 private constant PUSH_DEPLOYMENT_SALT = 1;
    uint88 private constant PULL_DEPLOYMENT_SALT = 2;

    function run() public {
        address warehouse = getAddressFromConfig("splitsWarehouse");

        bytes memory args = abi.encode(warehouse);

        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        bytes32 pull_salt = computeSalt(deployer, bytes11(PULL_DEPLOYMENT_SALT));
        bytes32 push_salt = computeSalt(deployer, bytes11(PUSH_DEPLOYMENT_SALT));

        vm.startBroadcast(privateKey);
        address pull_factory = create3(pull_salt, abi.encodePacked(type(PullSplitFactory).creationCode, args));
        address push_factory = create3(push_salt, abi.encodePacked(type(PushSplitFactory).creationCode, args));
        vm.stopBroadcast();

        updateDeployment(pull_factory, "PullSplitFactory");
        updateDeployment(push_factory, "PushSplitFactory");
    }
}
