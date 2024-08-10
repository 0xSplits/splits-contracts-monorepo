// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";

import { Signer, encodeSigner, encodeSigner } from "src/signers/Signer.sol";
import { SmartVault } from "src/vault/SmartVault.sol";
import { SmartVaultFactory } from "src/vault/SmartVaultFactory.sol";

contract SmartVaultFactoryTest is BaseTest {
    Signer[] signers;

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    PublicKey MIKE;

    address root = ALICE.addr;

    function setUp() public override {
        super.setUp();

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(encodeSigner(ALICE.addr));
        signers.push(encodeSigner(BOB.addr));
        signers.push(encodeSigner(MIKE.x, MIKE.y));
    }

    function test_implementation() public view {
        assertEq(SmartVault(payable(smartVaultFactory.IMPLEMENTATION())).FACTORY(), address(smartVaultFactory));
    }

    function test_createAccount() public {
        address predictedVault = smartVaultFactory.getAddress(root, signers, 1, 0);

        vm.expectEmit();
        emit SmartVaultFactory.SmartVaultCreated(predictedVault, root, signers, 1, 0);
        SmartVault deployedVault = smartVaultFactory.createAccount(root, signers, 1, 0);

        assertEq(predictedVault, address(deployedVault));
        assertEq(deployedVault.owner(), root);
        assertEq(deployedVault.getThreshold(), 1);
        assertEq(deployedVault.getSignerCount(), 3);
    }

    function test_getAddress() public {
        address predictedVault = smartVaultFactory.getAddress(root, signers, 1, 0);

        SmartVault deployedVault = smartVaultFactory.createAccount(root, signers, 1, 0);

        assertEq(predictedVault, address(deployedVault));
        assertEq(deployedVault.owner(), root);
        assertEq(deployedVault.getThreshold(), 1);
        assertEq(deployedVault.getSignerCount(), 3);
    }
}
