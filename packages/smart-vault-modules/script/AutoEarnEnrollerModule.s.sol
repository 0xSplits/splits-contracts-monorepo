// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnEnrollerModule } from "src/AutoEarnEnrollerModule.sol";
import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnEnrollerModuleScript is BaseScript {
    /// @dev Thrown when the recorded AutoEarnModuleV2, or its asset or vault, has no code on this chain.
    error AutoEarnModuleV2NotLive();

    function run() public {
        // The enroller is immutably bound to the AutoEarnModuleV2 recorded in this chain's deployments file. Deploy
        // that first with `AutoEarnModuleV2.s.sol`.
        string memory file = string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        AutoEarnModule autoEarnModuleV2 = AutoEarnModule(vm.parseJsonAddress(vm.readFile(file), ".AutoEarnModuleV2"));
        if (address(autoEarnModuleV2).code.length == 0) revert AutoEarnModuleV2NotLive();
        if (autoEarnModuleV2.ASSET().code.length == 0) revert AutoEarnModuleV2NotLive();
        if (autoEarnModuleV2.VAULT().code.length == 0) revert AutoEarnModuleV2NotLive();

        vm.startBroadcast();
        address module = address(
            new AutoEarnEnrollerModule{ salt: keccak256("splits.autoEarnEnrollerModule.v1") }(address(autoEarnModuleV2))
        );
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnEnrollerModule");
    }
}
