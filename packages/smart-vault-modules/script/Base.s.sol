// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Script } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";

contract BaseScript is Script {
    using stdJson for string;

    function getConfig() internal view returns (string memory) {
        string memory dir = string.concat(vm.projectRoot(), "/script/config/");
        string memory file = string.concat(vm.toString(block.chainid), ".json");
        return vm.readFile(string.concat(dir, file));
    }

    function getAddressFromConfig(string memory _key) internal view returns (address) {
        return getConfig().readAddress(string.concat(".", _key));
    }

    function getStringFromConfig(string memory _key) internal view returns (string memory) {
        return getConfig().readString(string.concat(".", _key));
    }

    function getUintFromConfig(string memory _key) internal view returns (uint256) {
        return getConfig().readUint(string.concat(".", _key));
    }

    function updateDeployment(address _contract, string memory _name) internal {
        if (isDryRun()) {
            return;
        }
        string memory directory = string.concat(vm.projectRoot(), "/deployments/");
        if (!vm.exists(directory)) {
            vm.createDir(directory, true);
        }

        string memory file = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        bool exists = vm.exists(file);
        if (!exists) {
            vm.writeFile(file, "{}");
        }

        string memory json = vm.readFile(file);
        if (vm.keyExists(json, string.concat(".", _name))) {
            vm.writeJson(vm.toString(_contract), file, string.concat(".", _name));
        } else {
            string memory root = "root";
            vm.serializeJson(root, json);
            vm.writeJson(vm.serializeAddress(root, _name, _contract), file);
        }
    }

    function isDryRun() internal view returns (bool) {
        return vm.envBool("DRY_RUN");
    }
}
