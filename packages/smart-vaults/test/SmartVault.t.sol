// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";
import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";
import { IAccount } from "src/interfaces/IAccount.sol";
import { UserOperationLib } from "src/library/UserOperationLib.sol";

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

    error Initialized();
    error OnlyEntryPoint();
    error OnlyFactory();
    error OnlyAccount();
    error OnlyRoot();
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

    function getUserOpSignature(SmartVault.SignatureWrapper[] memory signatures)
        internal
        pure
        returns (MultiSigner.UserOpSignature memory userOpsignature)
    {
        MultiSigner.NormalSignature memory normalSignature = MultiSigner.NormalSignature(signatures);

        userOpsignature =
            MultiSigner.UserOpSignature(MultiSigner.UserOpSignatureType.normal, abi.encode(normalSignature));
    }

    function getUserOpSignature(
        SmartVault.SignatureWrapper[] memory signatures,
        bytes32[] memory proof,
        bytes32 rootHash
    )
        internal
        pure
        returns (MultiSigner.UserOpSignature memory userOpsignature)
    {
        MultiSigner.NormalSignature memory normalSignature = MultiSigner.NormalSignature(signatures);
        MultiSigner.MultiChainSignature memory multiChainSignature =
            MultiSigner.MultiChainSignature(rootHash, proof, abi.encode(normalSignature));

        userOpsignature =
            MultiSigner.UserOpSignature(MultiSigner.UserOpSignatureType.multiChain, abi.encode(multiChainSignature));
    }

    function getRootSignature(SmartVault.SignatureWrapper[] memory signatures) internal pure returns (bytes memory) {
        MultiSigner.RootSignature memory signature =
            MultiSigner.RootSignature(MultiSigner.RootSignatureType.userOp, abi.encode(getUserOpSignature(signatures)));

        return abi.encode(signature);
    }

    function getRootSignature(
        SmartVault.SignatureWrapper[] memory signatures,
        bytes32[] memory proof,
        bytes32 rootHash
    )
        internal
        pure
        returns (bytes memory)
    {
        MultiSigner.RootSignature memory signature = MultiSigner.RootSignature(
            MultiSigner.RootSignatureType.userOp, abi.encode(getUserOpSignature(signatures, proof, rootHash))
        );

        return abi.encode(signature);
    }

    function getRootSignature(
        MultiSigner.SignerUpdate[] memory updates,
        SmartVault.SignatureWrapper[] memory signatures
    )
        internal
        pure
        returns (bytes memory)
    {
        MultiSigner.RootSignature memory signature = MultiSigner.RootSignature(
            MultiSigner.RootSignatureType.stateSync,
            abi.encode(getStateSyncSignature(updates, getUserOpSignature(signatures)))
        );

        return abi.encode(signature);
    }

    function getStateSyncSignature(
        MultiSigner.SignerUpdate[] memory updates,
        MultiSigner.UserOpSignature memory userOpSignature
    )
        internal
        pure
        returns (MultiSigner.StateSyncSignature memory signature)
    {
        signature = MultiSigner.StateSyncSignature(updates, abi.encode(userOpSignature));
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

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signatures);

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

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        signatures[1] = MultiSigner.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signatures);

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

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(
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
        userOp.signature = getRootSignature(signatures);

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
        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](0);

        _userOp.signature = getRootSignature(signatures);

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 0, 1));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_RevertsWhenNumberOfSignaturesLessThanThreshold(
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

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = getRootSignature(signatures);

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 1, 2));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(_userOp, _hash, _missingAccountsFund), 0);
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

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        signatures[1] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signatures);

        vm.expectRevert(abi.encodeWithSelector(DuplicateSigner.selector, 0));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
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

        SmartVault.SignatureWrapper[] memory signatures = new SmartVault.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        IAccount.PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(signatures);

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

        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(
            MultiSigner.SignerUpdateType.addSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(CAROL.key, hash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);

        assertEq(vault.signerCount(), 4);
        assertEq(vault.signerAtIndex(3), abi.encode(CAROL.addr));
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

        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(
            MultiSigner.SignerUpdateType.addSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);
        (v, r, s) = vm.sign(CAROL.key, hash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, signatures);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);

        hash = getUserOpHash(_userOp2);
        (v, r, s) = vm.sign(CAROL.key, hash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        userOp = _userOp2;
        userOp.signature = getRootSignature(signerUpdates, signatures);

        vm.expectRevert(abi.encodeWithSelector(MultiSigner.SignerUpdateValidationFailed.selector, signerUpdates[0]));
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOpWithLightStateSync_removeSigner(
        IAccount.PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(MultiSigner.SignerUpdateType.removeSigner, abi.encode(uint8(0)));

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(ALICE.key, hash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, signatures);

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
        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(MultiSigner.SignerUpdateType.updateThreshold, abi.encode(uint8(2)));

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(ALICE.key, hash);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        IAccount.PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, signatures);

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 1, 2));
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(userOp, hash, _missingAccountsFund);
    }

    /* -------------------------------------------------------------------------- */
    /*                        VALIDATE MULTI CHAIN USER OP                        */
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

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        IAccount.PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signatures, proof, rootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;

        userOp = _userOp2;
        userOp.signature = getRootSignature(signatures, proof, rootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash2, 0), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERC1271                                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_erc1271(bytes32 _hash) public {
        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signatures)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_newSigner(bytes32 _hash) public {
        address newSigner = CAROL.addr;

        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(
            MultiSigner.SignerUpdateType.addSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, signatures)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_newSigner_RevertsWhen_invalidNonce(bytes32 _hash) public {
        address newSigner = CAROL.addr;

        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(
            MultiSigner.SignerUpdateType.addSigner, abi.encode(abi.encode(newSigner), uint8(3))
        );

        bytes32 hash = keccak256(abi.encode(1, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(MultiSigner.SignerUpdateValidationFailed.selector, signerUpdates[0]));
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, signatures));
    }

    function testFuzz_erc1271_removeSigner(bytes32 _hash) public {
        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(MultiSigner.SignerUpdateType.removeSigner, abi.encode(uint8(0)));

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        (v, r, s) = vm.sign(BOB.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, signatures)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_removeSigner_RevertsWhen_signerAlreadyRemoved(bytes32 _hash) public {
        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(MultiSigner.SignerUpdateType.removeSigner, abi.encode(uint8(0)));

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        (v, r, s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(MultiSigner.InvalidSigner.selector, 0));
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, signatures));
    }

    function testFuzz_erc1271_updateThreshold_RevertsWhen_signaturesLessThanThreshold(bytes32 _hash) public {
        MultiSigner.SignerUpdateParam[] memory updates = new MultiSigner.SignerUpdateParam[](1);
        updates[0] = MultiSigner.SignerUpdateParam(MultiSigner.SignerUpdateType.updateThreshold, abi.encode(uint8(2)));

        bytes32 hash = keccak256(abi.encode(0, address(vault), updates));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSigner.SignatureWrapper[] memory signatures = new MultiSigner.SignatureWrapper[](1);
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        MultiSigner.SignerUpdate[] memory signerUpdates = new MultiSigner.SignerUpdate[](1);
        signerUpdates[0] = MultiSigner.SignerUpdate(updates, abi.encode(MultiSigner.NormalSignature(signatures)));

        (v, r, s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        signatures[0] = MultiSigner.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(MissingSignatures.selector, 1, 2));
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, signatures));
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
