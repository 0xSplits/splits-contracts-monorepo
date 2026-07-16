// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { ComposableExecutionModule } from "src/ComposableExecutionModule.sol";
import { Storage } from "src/vendor/composability/Storage.sol";

import { BaseScript } from "./Base.s.sol";

contract ComposableExecutionModuleScript is BaseScript {
    function run() public {
        vm.startBroadcast();
        address store = address(new Storage{ salt: keccak256("splits.composabilityStorage.v1") }());
        address module =
            address(new ComposableExecutionModule{ salt: keccak256("splits.composableExecutionModule.v1") }());
        vm.stopBroadcast();

        updateDeployment(store, "ComposabilityStorage");
        updateDeployment(module, "ComposableExecutionModule");
    }
}
