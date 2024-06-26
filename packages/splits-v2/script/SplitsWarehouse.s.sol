// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitsWarehouse } from "../src/SplitsWarehouse.sol";

import { BaseScript } from "./Base.s.sol";

contract SplitsWarehouseScript is BaseScript {
    uint88 private constant DEPLOYMENT_SALT = 0;

    function run() public {
        string memory name = getStringFromConfig("nativeTokenName");
        string memory symbol = getStringFromConfig("nativeTokenSymbol");

        bytes memory args = abi.encode(name, symbol);

        address deployer = vm.envAddress("DEPLOYER");

        bytes32 salt = computeSalt(deployer, bytes11(DEPLOYMENT_SALT));

        vm.startBroadcast();
        address warehouse = create3(salt, abi.encodePacked(type(SplitsWarehouse).creationCode, args));
        vm.stopBroadcast();
        updateDeployment(warehouse, "SplitsWarehouse");
    }
}
