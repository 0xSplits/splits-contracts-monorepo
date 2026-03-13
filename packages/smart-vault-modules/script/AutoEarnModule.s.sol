// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnModuleScript is BaseScript {
    /// @dev Base USDC address.
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Base Aave USDC earn vault address.
    address constant AAVE_VAULT = 0x4EA71A20e655794051D1eE8b6e4A3269B13ccaCc;

    function run() public {
        vm.startBroadcast();
        address module = address(new AutoEarnModule{ salt: keccak256("splits.autoEarnModule.v1") }(USDC, AAVE_VAULT));
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnModule");
    }
}
