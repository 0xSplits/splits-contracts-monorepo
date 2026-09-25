// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { AutoEarnModule } from "src/AutoEarnModule.sol";

import { BaseScript } from "./Base.s.sol";

contract AutoEarnModuleV2Script is BaseScript {
    /// @dev Thrown when this script has no USDC or earn vault address for the chain.
    error UnsupportedChain();

    /// @dev Base USDC address.
    address constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Base Splits Earn USDC vault address (fee wrapper over Steakhouse Prime USDC V2).
    address constant BASE_EARN_VAULT = 0x189A1a23F46321a196646314E6a078a404513C8F;

    /// @dev Mainnet USDC address.
    address constant MAINNET_USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    /// @dev Mainnet Splits Earn USDC vault address (fee wrapper over Steakhouse Prime USDC V2).
    address constant MAINNET_EARN_VAULT = 0xF5730f6F5bcc2a3E98dA199F40b1A8aF1Ac37A43;

    function run() public {
        (address usdc, address earnVault) = _getAddresses();

        vm.startBroadcast();
        address module = address(new AutoEarnModule{ salt: keccak256("splits.autoEarnModule.v2") }(usdc, earnVault));
        vm.stopBroadcast();

        updateDeployment(module, "AutoEarnModuleV2");
    }

    function _getAddresses() internal view returns (address usdc, address earnVault) {
        if (block.chainid == 8453) return (BASE_USDC, BASE_EARN_VAULT);
        if (block.chainid == 1) return (MAINNET_USDC, MAINNET_EARN_VAULT);
        revert UnsupportedChain();
    }
}
