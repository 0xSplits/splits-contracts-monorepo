// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { BaseScript } from "./Base.s.sol";

/// Deploys SmartVaultFactory at its canonical address from the recorded init code, not from `src`. The CREATE2 address
/// commits to the compiled bytecode, whose metadata hash changes with any edit to the source text, formatting included,
/// so a fresh build lands somewhere else. `deployments/standard-input/vaultFactory.verify.json` reproduces the recorded
/// init code with solc 0.8.23.
contract VaultFactoryScript is BaseScript {
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 internal constant SALT = keccak256("splits.smartVaultFactory.v1");
    address internal constant FACTORY = 0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C;

    /// @dev Thrown when the recorded init code doesn't hash to the canonical factory address.
    error InitCodeMismatch();
    /// @dev Thrown when the chain has no CREATE2 deployer at its usual address.
    error Create2DeployerMissing();
    /// @dev Thrown when the deployment leaves no code at the factory address.
    error DeploymentFailed();

    function run() public {
        string memory json =
            vm.readFile(string.concat(vm.projectRoot(), "/deployments/initcode/SmartVaultFactory.json"));
        bytes memory initCode = vm.parseJsonBytes(json, ".SmartVaultFactory");
        if (computeCreate2Address(SALT, keccak256(initCode), CREATE2_DEPLOYER) != FACTORY) revert InitCodeMismatch();
        if (CREATE2_DEPLOYER.code.length == 0) revert Create2DeployerMissing();

        if (FACTORY.code.length == 0) {
            vm.startBroadcast();
            // solhint-disable-next-line avoid-low-level-calls
            (bool success,) = CREATE2_DEPLOYER.call(abi.encodePacked(SALT, initCode));
            vm.stopBroadcast();
            if (!success || FACTORY.code.length == 0) revert DeploymentFailed();
        }

        updateDeployment(FACTORY, "SmartVaultFactory");
    }
}
