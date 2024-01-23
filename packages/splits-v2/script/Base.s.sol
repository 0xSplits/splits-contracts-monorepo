// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { ICreateX } from "./ICreateX.sol";
import { Script } from "forge-std/Script.sol";
import { stdJson } from "forge-std/stdJson.sol";

contract BaseScript is Script {
    using stdJson for string;

    ICreateX immutable CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function getConfig() internal view returns (string memory) {
        string memory inputDir = string.concat(vm.projectRoot(), "/script/config/");
        string memory chainDir = string.concat(vm.toString(block.chainid), "/");
        string memory file = string.concat("config.json");
        return vm.readFile(string.concat(inputDir, chainDir, file));
    }

    function getAddressFromConfig(string memory _key) internal view returns (address) {
        return getConfig().readAddress(_key);
    }

    function getStringFromConfig(string memory _key) internal view returns (string memory) {
        return getConfig().readString(_key);
    }

    function getUintFromConfig(string memory _key) internal view returns (uint256) {
        return getConfig().readUint(_key);
    }

    function create3(bytes32 salt, bytes memory initCode) internal returns (address) {
        return CREATEX.deployCreate3(salt, initCode);
    }

    function computeSalt(address deployer, bytes11 _salt) internal pure returns (bytes32) {
        // keccak256(abi.encodePacked(deployer, hex"01", _salt))
        return bytes32(abi.encodePacked(deployer, hex"01", _salt));
    }
}
