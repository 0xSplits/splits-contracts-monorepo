// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnModuleScript is BaseScript {
    function run() public {
        address usdc = getAddressFromConfig("usdc");
        address vault = getAddressFromConfig("aaveUsdcVault");

        vm.startBroadcast();
        address module = address(new AutoEarnModule{ salt: keccak256("splits.autoEarnModule.v1") }(usdc, vault));
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnModule");
    }
}
