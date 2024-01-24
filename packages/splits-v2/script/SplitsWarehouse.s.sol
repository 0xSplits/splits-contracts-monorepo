// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { SplitsWarehouse } from "../src/SplitsWarehouse.sol";

import { BaseScript } from "./Base.s.sol";
import { console2 } from "forge-std/console2.sol";

contract SplitsWarehouseScript is BaseScript {
    uint88 constant DEPLOYMENT_SALT = 0;

    function run() public {
        string memory name = getStringFromConfig("nativeTokenName");
        string memory symbol = getStringFromConfig("nativeTokenSymbol");

        bytes memory args = abi.encode(name, symbol);

        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        bytes32 salt = computeSalt(deployer, bytes11(DEPLOYMENT_SALT));

        vm.startBroadcast(privateKey);
        address warehouse = create3(salt, abi.encodePacked(type(SplitsWarehouse).creationCode, args));
        vm.stopBroadcast();
        updateDeployment(warehouse, "SplitsWarehouse");
    }
}
