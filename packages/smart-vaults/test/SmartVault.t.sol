// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";
import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";
import { IAccount } from "src/interfaces/IAccount.sol";

import { MultiSignerSignatureLib } from "src/library/MultiSignerSignatureLib.sol";
import { UserOperationLib } from "src/library/UserOperationLib.sol";

import { Ownable } from "solady/auth/Ownable.sol";
import { LightSyncMultiSigner } from "src/utils/LightSyncMultiSigner.sol";
import { MultiSigner } from "src/utils/MultiSigner.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

import { console } from "forge-std/console.sol";

contract SmartVaultTest is BaseTest {
    using UserOperationLib for IAccount.PackedUserOperation;

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

    error OnlyEntryPoint();
    error OnlyFactory();
    error OnlySelfOrOwner();
    error Unauthorized();
    error InvalidSignerBytesLength(bytes signer);
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);
    error DuplicateSigner(uint8 signerIndex);

    function setUp() public override {
        super.setUp();

        root = ALICE.addr;

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(abi.encode(ALICE.addr));
        signers.push(abi.encode(BOB.addr));
        signers.push(passkeyOwner);

        vault = smartVaultFactory.createAccount(root, signers, 1, 0);
    }

    function getUserOpHash(IAccount.PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRY_POINT, block.chainid));
    }

    function getLightUserOpHash(IAccount.PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hashLight(), ENTRY_POINT, block.chainid));
    }

    function getUserOpSignature(MultiSignerSignatureLib.SignatureWrapper[] memory sigs)
        internal
        pure
        returns (SmartVault.UserOpSignature memory userOpSignature)
    {
        MultiSignerSignatureLib.Signature memory normalSignature = MultiSignerSignatureLib.Signature(sigs);

        userOpSignature = SmartVault.UserOpSignature(SmartVault.UserOpSignatureType.Single, abi.encode(normalSignature));
    }

    function getUserOpSignature(
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs,
        bytes32[] memory proof,
        bytes32[] memory lightProof,
        bytes32 rootHash,
        bytes32 lightRootHash
    )
        internal
        pure
        returns (SmartVault.UserOpSignature memory userOpSignature)
    {
        MultiSignerSignatureLib.Signature memory normalSignature = MultiSignerSignatureLib.Signature(sigs);
        SmartVault.MultiOpSignature memory multiChainSignature =
            SmartVault.MultiOpSignature(lightRootHash, lightProof, rootHash, proof, abi.encode(normalSignature));

        userOpSignature =
            SmartVault.UserOpSignature(SmartVault.UserOpSignatureType.Multi, abi.encode(multiChainSignature));
    }

    function getRootSignature(MultiSignerSignatureLib.SignatureWrapper[] memory sigs)
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.Signature memory signature =
            SmartVault.Signature(SmartVault.SignatureType.UserOp, abi.encode(getUserOpSignature(sigs)));

        return abi.encode(signature);
    }

    function getRootSignature(
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs,
        bytes32[] memory proof,
        bytes32[] memory lightProof,
        bytes32 rootHash,
        bytes32 lightRootHash
    )
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.Signature memory signature = SmartVault.Signature(
            SmartVault.SignatureType.UserOp,
            abi.encode(getUserOpSignature(sigs, proof, lightProof, rootHash, lightRootHash))
        );

        return abi.encode(signature);
    }

    function getRootSignature(
        SmartVault.SignerSetUpdate[] memory updates,
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs,
        bytes32[] memory proof,
        bytes32[] memory lightProof,
        bytes32 rootHash,
        bytes32 lightRootHash
    )
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.Signature memory signature = SmartVault.Signature(
            SmartVault.SignatureType.LightSync,
            abi.encode(
                getStateSyncSignature(updates, getUserOpSignature(sigs, proof, lightProof, rootHash, lightRootHash))
            )
        );

        return abi.encode(signature);
    }

    function getRootSignature(
        SmartVault.SignerSetUpdate[] memory updates,
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs
    )
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.Signature memory signature = SmartVault.Signature(
            SmartVault.SignatureType.LightSync, abi.encode(getStateSyncSignature(updates, getUserOpSignature(sigs)))
        );

        return abi.encode(signature);
    }

    function getStateSyncSignature(
        LightSyncMultiSigner.SignerSetUpdate[] memory updates,
        SmartVault.UserOpSignature memory userOpSignature
    )
        internal
        pure
        returns (SmartVault.LightSyncSignature memory signature)
    {
        signature = SmartVault.LightSyncSignature(updates, abi.encode(userOpSignature));
    }

    function hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
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
        IAccount.PackedUserOperation memory userOp,
        bytes32 hash
    )
        public
    {
        vm.expectRevert(abi.encodeWithSelector(OnlyEntryPoint.selector));
        vault.validateUserOp(userOp, hash, 1);
    }

    function testFuzz_validateUserOp_singleEOA(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_multipleEOA(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ALICE.addr);
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singlePasskey(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(hash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(
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

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhen_badSignature(
        IAccount.PackedUserOperation memory _userOp,
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
        IAccount.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](0);

        _userOp.signature = getRootSignature(sigs);

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(_userOp, _hash, _missingAccountsFund);
    }

    function testFuzz_validateUserOp_WhenNumberOfSignaturesLessThanThreshold(
        IAccount.PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(ALICE.addr);
        vault.updateThreshold(2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_RevertsWhenDuplicateSigner(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        vm.prank(ALICE.addr);
        vault.updateThreshold(2);

        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_RevertsWhenBadEOASigner(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        IAccount.PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                   VALIDATE USER OP WITH LIGHT STATE SYNC                   */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateUserOpWithLightStateSync_newSigner(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        address newSigner = CAROL.addr;

        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.AddSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(CAROL.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);

        assertEq(vault.getSignerCount(), 4);
        assertEq(vault.getSignerAtIndex(3), abi.encode(CAROL.addr));
        assertEq(vault.getNonce(), 1);
    }

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_invalidNonce(
        IAccount.PackedUserOperation calldata _userOp1,
        IAccount.PackedUserOperation calldata _userOp2,
        uint256 _missingAccountsFund
    )
        public
    {
        address newSigner = CAROL.addr;

        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.AddSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);
        (v, r, s) = vm.sign(CAROL.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);

        hash = getUserOpHash(_userOp2);
        (v, r, s) = vm.sign(CAROL.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        userOp = _userOp2;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.expectRevert(
            abi.encodeWithSelector(LightSyncMultiSigner.SignerSetUpdateValidationFailed.selector, signerUpdates[0])
        );
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOpWithLightStateSync_removeSigner(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.RemoveSigner, abi.encode(uint8(0))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
        assertEq(vault.getNonce(), 1);
    }

    function testFuzz_validateUserOpWithLightStateSync_updateThreshold_RevertsWhen_signaturesLessThanThreshold(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.UpdateThreshold, abi.encode(uint8(2))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                        VALIDATE MULTI USER OP                        */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateMultiUserOp(
        IAccount.PackedUserOperation calldata _userOp1,
        IAccount.PackedUserOperation calldata _userOp2
    )
        public
    {
        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, rootHash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        IAccount.PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(sigs, proof, new bytes32[](0), rootHash, bytes32(0));

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;

        userOp = _userOp2;
        userOp.signature = getRootSignature(sigs, proof, new bytes32[](0), rootHash, bytes32(0));

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash2, 0), 0);
    }

    function testFuzz_validateMultiUserOp_withMultipleSigners(
        IAccount.PackedUserOperation calldata _userOp1,
        IAccount.PackedUserOperation calldata _userOp2
    )
        public
    {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.UpdateThreshold, abi.encode(uint8(2))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);

        (v, r, s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        bytes32[] memory lightProof = new bytes32[](1);
        lightProof[0] = lightHash2;

        IAccount.PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, sigs, proof, lightProof, rootHash, lightRootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;
        lightProof[0] = lightHash1;

        userOp = _userOp2;
        userOp.signature = getRootSignature(sigs, proof, lightProof, rootHash, lightRootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash2, 0), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERC1271                                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_erc1271(bytes32 _hash) public {
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_newSigner(bytes32 _hash) public {
        address newSigner = CAROL.addr;

        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.AddSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_newSigner_RevertsWhen_invalidNonce(bytes32 _hash) public {
        address newSigner = CAROL.addr;

        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.AddSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(1, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.expectRevert(
            abi.encodeWithSelector(LightSyncMultiSigner.SignerSetUpdateValidationFailed.selector, signerUpdates[0])
        );
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs));
    }

    function testFuzz_erc1271_removeSigner(bytes32 _hash) public {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.RemoveSigner, abi.encode(uint8(0))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        (v, r, s) = vm.sign(BOB.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_removeSigner_RevertsWhen_signerAlreadyRemoved(bytes32 _hash) public {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.RemoveSigner, abi.encode(uint8(0))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        (v, r, s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0xffffffff);
    }

    function testFuzz_erc1271_updateThreshold_RevertsWhen_signaturesLessThanThreshold(bytes32 _hash) public {
        LightSyncMultiSigner.SignerUpdateParam[] memory updates = new LightSyncMultiSigner.SignerUpdateParam[](1);
        updates[0] = LightSyncMultiSigner.SignerUpdateParam(
            LightSyncMultiSigner.SignerUpdateType.UpdateThreshold, abi.encode(uint8(2))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] =
            LightSyncMultiSigner.SignerSetUpdate(updates, abi.encode(MultiSignerSignatureLib.Signature(sigs)));

        (v, r, s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs));
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
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector));
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
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector));
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
        vm.expectRevert(OnlySelfOrOwner.selector);
        vm.prank(ENTRY_POINT);
        vault.deployCreate(abi.encodePacked(type(SmartVault).creationCode, abi.encode(root)));
    }

    /* -------------------------------------------------------------------------- */
    /*                                  OWNERSHIP                                 */
    /* -------------------------------------------------------------------------- */

    function test_transferOwnership() public {
        vm.expectEmit();
        emit Ownable.OwnershipTransferred(vault.owner(), BOB.addr);
        vm.prank(vault.owner());
        vault.transferOwnership(BOB.addr);

        assertEq(vault.owner(), BOB.addr);
    }

    function test_transferOwnership_RevertsWhen_notOwner() public {
        vm.expectRevert(Unauthorized.selector);
        vault.transferOwnership(BOB.addr);
    }

    /* -------------------------------------------------------------------------- */
    /*                             SIGNER SET UPDATES                             */
    /* -------------------------------------------------------------------------- */

    function testFuzz_addSigner_RevertWhen_callerNotOwner(bytes memory _signer, address _caller) public {
        vm.assume(_caller != ALICE.addr && _caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelfOrOwner.selector);
        vault.addSigner(_signer, 0);
        vm.stopPrank();
    }

    function testFuzz_removeSigner_RevertWhen_callerNotOwner(uint8 _index, address _caller) public {
        vm.assume(_caller != ALICE.addr && _caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelfOrOwner.selector);
        vault.removeSigner(_index);
        vm.stopPrank();
    }

    function testFuzz_updateThreshold_RevertWhen_callerNotOwner(uint8 _threshold, address _caller) public {
        vm.assume(_caller != ALICE.addr && _caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelfOrOwner.selector);
        vault.updateThreshold(_threshold);
        vm.stopPrank();
    }

    function testFuzz_setNonce_RevertWhen_callerNotOwner(uint8 _nonce, address _caller) public {
        vm.assume(_caller != ALICE.addr && _caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelfOrOwner.selector);
        vault.setNonce(_nonce);
        vm.stopPrank();
    }
}
