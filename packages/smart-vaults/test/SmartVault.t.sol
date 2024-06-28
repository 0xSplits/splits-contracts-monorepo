// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";

import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

import { console } from "forge-std/console.sol";

contract SmartVaultTest is BaseTest {
    bytes[] signers;

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    PublicKey MIKE;

    address root;

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
    error OnlyRoot();
    error InvalidSignerBytesLength(bytes signer);
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);
    error DuplicateSigner(bytes signer, uint8 signerIndex);

    function setUp() public override {
        super.setUp();

        root = ALICE.addr;

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(abi.encode(ALICE.addr));
        signers.push(abi.encode(BOB.addr));
        signers.push(passkeyOwner);

        vault = smartVaultFactory.createAccount(root, signers, 1, 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 INITIALIZE                                 */
    /* -------------------------------------------------------------------------- */

    function test_initialize_RevertsWhen_notFactory() public {
        vm.expectRevert(abi.encodeWithSelector(OnlyFactory.selector));
        vault.initialize(root, signers, 1);
    }

    function test_entryPoint() public view {
        assertEq(vault.entryPoint(), ENTRY_POINT);
    }

    /* -------------------------------------------------------------------------- */
    /*                               VALIDATE USEROP                              */
    /* -------------------------------------------------------------------------- */

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

    function testFuzz_validateUserOp_RevertsWhen_badSignature(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhenEmptySignatures(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](0);

        _userOp.signature = abi.encode(signatures);

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 0, 1));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhenNumberOfSignaturesLessThanThreshold(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(ALICE.addr);
        vault.updateThreshold(2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = abi.encode(signatures);

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 1, 2));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhenDuplicateSigner(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(ALICE.addr);
        vault.updateThreshold(2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](2);
        signatures[0] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        signatures[1] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = abi.encode(signatures);

        vm.expectRevert(abi.encodeWithSelector(DuplicateSigner.selector, abi.encode(ALICE.addr), 0));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhenBadEOASigner(
        SmartVault.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = SmartVault.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = abi.encode(signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EXECUTE                                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_execute(address target, uint256 value, bool _root) public {
        vm.assume(target.code.length == 0);
        assumeNotPrecompile(target);
        vm.deal(address(vault), value);

        vm.prank(_root ? root : ENTRY_POINT);
        vault.execute(target, value, "0x");
    }

    function testFuzz_execute_revertsWhenNotRootOrEntryPoint(address target, uint256 value, bytes memory data) public {
        vm.expectRevert(abi.encodeWithSelector(OnlyRoot.selector));
        vault.execute(target, value, data);
    }

    function testFuzz_execute_revertsWhenBadCall(address target, uint256 value, bytes memory data) public {
        vm.assume(target.code.length == 0 && value > 0);
        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.execute(target, value, data);
    }

    /* -------------------------------------------------------------------------- */
    /*                                EXECUTE BATCH                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_executeBatch(address target, uint256 value, bool _root) public {
        vm.assume(target.code.length == 0);
        assumeNotPrecompile(target);
        vm.deal(address(vault), value);

        SmartVault.Call[] memory calls = new SmartVault.Call[](1);
        calls[0] = SmartVault.Call(target, value, "0x");

        vm.prank(_root ? root : ENTRY_POINT);
        vault.executeBatch(calls);
    }

    function test_executeBatch_revertsWhenNotRootOrEntryPoint() public {
        vm.expectRevert(abi.encodeWithSelector(OnlyRoot.selector));
        vault.executeBatch(new SmartVault.Call[](0));
    }

    function testFuzz_executeBatch_revertsWhenBadCall(address target, uint256 value, bytes memory data) public {
        vm.assume(target.code.length == 0 && value > 0);
        vm.expectRevert();

        SmartVault.Call[] memory calls = new SmartVault.Call[](1);
        calls[0] = SmartVault.Call(target, value, data);

        vm.prank(ENTRY_POINT);
        vault.executeBatch(calls);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   CREATE                                   */
    /* -------------------------------------------------------------------------- */

    function test_deployCreate() public {
        vm.prank(ENTRY_POINT);
        vault.execute(
            address(vault),
            0,
            abi.encodeWithSelector(
                SmartVault.deployCreate.selector, abi.encodePacked(type(SmartVault).creationCode, abi.encode(root))
            )
        );
    }

    function test_deployCreate_RevertsWhen_callerNotAccount() public {
        vm.expectRevert(OnlyAccount.selector);
        vm.prank(ENTRY_POINT);
        vault.deployCreate(abi.encodePacked(type(SmartVault).creationCode, abi.encode(root)));
    }
}
