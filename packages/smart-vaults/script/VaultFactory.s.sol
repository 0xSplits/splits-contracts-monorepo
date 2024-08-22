// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SmartVaultFactory } from "src/vault/SmartVaultFactory.sol";

import { BaseScript } from "./Base.s.sol";

contract VaultFactoryScript is BaseScript {
    function run() public {
        vm.startBroadcast();
        address factory = address(new SmartVaultFactory{ salt: keccak256("splits.smartVaultFactory.v1") }());
        vm.stopBroadcast();

        updateDeployment(factory, "SmartVaultFactory");
    }
}
