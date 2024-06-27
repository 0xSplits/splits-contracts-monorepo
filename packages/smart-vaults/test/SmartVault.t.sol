// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";

import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

contract SmartVaultTest is BaseTest {
    bytes[] signers;

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    PublicKey MIKE;

    address root = ALICE.addr;

    SmartVault vault;

    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);

    // solhint-disable
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    // solhint-enable

    error Initialized();
    error OnlyEntryPoint();
    error OnlyFactory();
    error OnlyAccount();
    error InvalidSignerBytesLength(bytes signer);

    function setUp() public override {
        super.setUp();

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(abi.encode(ALICE.addr));
        signers.push(abi.encode(BOB.addr));
        signers.push(passkeyOwner);

        vault = smartVaultFactory.createAccount(root, signers, 1, 0);
    }

    function test_initialize_RevertsWhen_notFactory() public {
        vm.expectRevert(abi.encodeWithSelector(OnlyFactory.selector));
        vault.initialize(root, signers, 1);
    }

    function test_entryPoint() public view {
        assertEq(vault.entryPoint(), ENTRY_POINT);
    }

    function testFuzz_validateUserOp_RevertsWhen_callerNotEntryPoint(
        SmartVault.PackedUserOperation memory userOp,
        bytes32 hash
    )
        public
    {
        vm.expectRevert(abi.encodeWithSelector(OnlyEntryPoint.selector));
        vault.validateUserOp(userOp, hash, 1);
    }

    function testFuzz_validateUserOp_singleEOA(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        _userOp.signature = abi.encode(signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_multipleEOA(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](2);
        signatures[0] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, _hash);
        signatures[1] = SmartVault.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        _userOp.signature = abi.encode(signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singlePasskey(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(_hash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = SmartVault.SignatureWrapper(
            2,
            abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: uint256(r),
                    s: uint256(s)
                })
            )
        );

        _userOp.signature = abi.encode(signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }
}
