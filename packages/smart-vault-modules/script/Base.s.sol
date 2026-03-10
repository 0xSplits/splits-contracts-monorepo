// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Script } from "forge-std/Script.sol";

contract BaseScript is Script {
    function updateDeployment(address _contract, string memory _name) internal {
        if (vm.envBool("DRY_RUN")) return;

        string memory directory = string.concat(vm.projectRoot(), "/deployments/");
        if (!vm.exists(directory)) vm.createDir(directory, true);

        string memory file = string.concat(directory, vm.toString(block.chainid), ".json");
        if (!vm.exists(file)) vm.writeFile(file, "{}");

        string memory json = vm.readFile(file);
        if (vm.keyExists(json, string.concat(".", _name))) {
            vm.writeJson(vm.toString(_contract), file, string.concat(".", _name));
        } else {
            string memory root = "root";
            vm.serializeJson(root, json);
            vm.writeJson(vm.serializeAddress(root, _name, _contract), file);
        }
    }
}
