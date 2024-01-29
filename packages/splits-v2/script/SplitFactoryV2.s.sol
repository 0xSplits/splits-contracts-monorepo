// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { SplitFactoryV2 } from "../src/splitters/SplitFactoryV2.sol";

import { BaseScript } from "./Base.s.sol";

contract SplitFactoryV2Script is BaseScript {
    uint88 private constant DEPLOYMENT_SALT = 1;

    function run() public {
        address warehouse = getAddressFromConfig("splitsWarehouse");

        bytes memory args = abi.encode(warehouse);

        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        bytes32 salt = computeSalt(deployer, bytes11(DEPLOYMENT_SALT));

        vm.startBroadcast(privateKey);
        address factory = create3(salt, abi.encodePacked(type(SplitFactoryV2).creationCode, args));
        vm.stopBroadcast();
        updateDeployment(factory, "SplitFactoryV2");
    }
}
