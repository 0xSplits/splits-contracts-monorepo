// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnModuleV2Script is BaseScript {
    /// @dev Base USDC address.
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Base Splits Earn USDC vault address (fee wrapper over Steakhouse Prime USDC V2).
    address constant EARN_VAULT = 0x189A1a23F46321a196646314E6a078a404513C8F;

    function run() public {
        vm.startBroadcast();
        address module = address(new AutoEarnModule{ salt: keccak256("splits.autoEarnModule.v2") }(USDC, EARN_VAULT));
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnModuleV2");
    }
}
