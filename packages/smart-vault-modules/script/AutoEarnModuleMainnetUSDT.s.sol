// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnModuleMainnetUSDT } from "src/AutoEarnModuleMainnetUSDT.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnModuleMainnetUSDTScript is BaseScript {
    /// @dev Thrown when this script is not run on mainnet.
    error UnsupportedChain();

    /// @dev Mainnet USDT address.
    address constant MAINNET_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    /// @dev Mainnet Splits Earn USDT vault address (fee wrapper over Steakhouse Prime USDT).
    address constant MAINNET_EARN_VAULT = 0xb5aeE31903Eb465DeF0ad08fE4A88D77D58100Db;

    function run() public {
        if (block.chainid != 1) revert UnsupportedChain();

        vm.startBroadcast();
        address module = address(
            new AutoEarnModuleMainnetUSDT{ salt: keccak256("splits.autoEarnModuleMainnetUSDT.v1") }(
                MAINNET_USDT, MAINNET_EARN_VAULT
            )
        );
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnModuleMainnetUSDT");
    }
}
