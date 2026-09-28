// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnEnrollerModule } from "src/AutoEarnEnrollerModule.sol";
import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnEnrollerModuleScript is BaseScript {
    /// @dev Thrown when the supplied AutoEarnModuleV2, or its asset or vault, has no code on this chain.
    error AutoEarnModuleV2NotLive();

    /// @param autoEarnModule_ The AutoEarnModuleV2 address already deployed on the selected chain.
    function run(address autoEarnModule_) public {
        AutoEarnModule autoEarnModuleV2 = AutoEarnModule(autoEarnModule_);
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
