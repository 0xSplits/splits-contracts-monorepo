// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";
import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";

import { MultiSignerSignatureLib } from "src/library/MultiSignerSignatureLib.sol";
import { UserOperationLib } from "src/library/UserOperationLib.sol";

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { LightSyncMultiSigner } from "src/utils/LightSyncMultiSigner.sol";
import { MultiSigner } from "src/utils/MultiSigner.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

import { MockERC721 } from "./mocks/MockERC721.sol";
import { console } from "forge-std/console.sol";

import { ERC7211FallbackHandler, IERC7211Receiver, MockERC7211 } from "./mocks/MockERC7211.sol";

contract SmartVaultTest is BaseTest {
    using UserOperationLib for PackedUserOperation;

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
    error OnlySelf();
    error Unauthorized();
    error InvalidSignerBytesLength(bytes signer);
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);
    error DuplicateSigner(uint8 signerIndex);
    error InvalidNumberOfSigners();
    error InvalidThreshold();
    error InvalidNonce();
    error InvalidEthereumAddressOwner(bytes signer);
    error InvalidMerkleProof();
    error SignerAlreadyPresent(uint8 index);
    error SignerNotPresent(uint8 index);
    error FunctionNotSupported(bytes4 sig);

    event UpdatedFallbackHandler(bytes4 indexed sig, address indexed handler);
    event ReceiveEth(address indexed sender, uint256 amount);

    MockERC721 nft;

    function setUp() public override {
        super.setUp();

        root = ALICE.addr;

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(abi.encode(ALICE.addr));
        signers.push(abi.encode(BOB.addr));
        signers.push(passkeyOwner);

        vault = smartVaultFactory.createAccount(root, signers, 1, 0);

        nft = new MockERC721();
    }

    function getUserOpHash(PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRY_POINT, block.chainid));
    }

    function getLightUserOpHash(PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hashLight(), ENTRY_POINT, block.chainid));
    }

    function getUserOpSignature(MultiSignerSignatureLib.SignatureWrapper[] memory sigs)
        internal
        pure
        returns (SmartVault.UserOpSignature memory userOpSignature)
    {
        userOpSignature = SmartVault.UserOpSignature(SmartVault.UserOpSignatureType.Single, abi.encode(sigs));
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
        SmartVault.MerkelizedOpSignature memory multiChainSignature =
            SmartVault.MerkelizedOpSignature(lightRootHash, lightProof, rootHash, proof, abi.encode(sigs));

        userOpSignature =
            SmartVault.UserOpSignature(SmartVault.UserOpSignatureType.Merkelized, abi.encode(multiChainSignature));
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

    function test_initialize() public {
        vm.prank(address(smartVaultFactory));
        vault.initialize(BOB.addr, signers, 2);

        assertEq(vault.owner(), BOB.addr);
        assertEq(vault.getThreshold(), 2);
    }

    function test_initialize_RevertsWhen_signersIsZero() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidNumberOfSigners.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, new bytes[](0), 1);
    }

    function test_initialize_RevertsWhen_signersIsGreaterThan255() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidNumberOfSigners.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, new bytes[](256), 1);
    }

    function test_initialize_RevertsWhen_thresholdIsZero() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidThreshold.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, signers, 0);
    }

    function test_initialize_RevertsWhen_thresholdIsGreaterThanSigners() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidThreshold.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, signers, 4);
    }

    function testFuzz_initialize_RevertsWhen_invalidSignerBytesLength(bytes memory signer_) public {
        vm.assume(signer_.length != 32 && signer_.length != 64);

        bytes[] memory signers__ = new bytes[](1);
        signers__[0] = signer_;

        vm.expectRevert(abi.encodeWithSelector(InvalidSignerBytesLength.selector, signer_));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, signers__, 1);
    }

    function testFuzz_initialize_RevertsWhen_invalidEthereumAddressOwner(uint256 signer_) public {
        vm.assume(signer_ > type(uint160).max);

        bytes[] memory signers__ = new bytes[](1);
        signers__[0] = abi.encode(signer_);

        vm.expectRevert(abi.encodeWithSelector(InvalidEthereumAddressOwner.selector, signers__[0]));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, signers__, 1);
    }

    function test_initialize_RevertsWhen_notFactory() public {
        vm.expectRevert(abi.encodeWithSelector(OnlyFactory.selector));
        vault.initialize(root, signers, 1);
    }

    function test_entryPoint() public view {
        assertEq(vault.entryPoint(), ENTRY_POINT);
    }

    /* -------------------------------------------------------------------------- */
    /*                               VALIDATE USER OP                             */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateUserOp_RevertsWhen_callerNotEntryPoint(
        PackedUserOperation memory userOp,
        bytes32 hash
    )
        public
    {
        vm.expectRevert(abi.encodeWithSelector(OnlyEntryPoint.selector));
        vault.validateUserOp(userOp, hash, 1);
    }

    function testFuzz_validateUserOp_RevertsWhen_badSignature(
        PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(_userOp, _hash, _missingAccountsFund);
    }

    /* -------------------------------------------------------------------------- */
    /*                           VALIDATE SINGLE USER OP                          */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateUserOp_singleUserOp_singleEOA(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA(
        PackedUserOperation calldata _userOp,
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

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_singlePasskey(
        PackedUserOperation calldata _userOp,
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

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_RevertsWhen_emptySignatures(
        PackedUserOperation memory _userOp,
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

    function testFuzz_validateUserOp_singleUserOp_RevertsWhen_numberOfSignaturesLessThanThreshold(
        PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, _hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = getRootSignature(sigs);

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(_userOp, _hash, _missingAccountsFund);
    }

    function testFuzz_validateUserOp_singleUserOp_duplicateSigner(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_incorrectSignerIndex(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, hash);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_WhenThresholdIs2_incorrectSignerIndexLightHash(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_WhenThresholdIs2_incorrectSignerIndex(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_fakedSignature(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund,
        bytes32 _hash
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);
        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, _hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_WhenThresholdIs2_fakedSignatureLight(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes32 hash = getUserOpHash(_userOp);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_WhenThresholdIs2_fakedSignature(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        vm.deal(address(vault), _missingAccountsFund);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, lightHash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getRootSignature(sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                           VALIDATE Merkelized USER OP                          */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateMerkelizedUserOp_whenThresholdIs1(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2
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

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(sigs, proof, new bytes32[](0), rootHash, bytes32(0));

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;

        userOp = _userOp2;
        userOp.signature = getRootSignature(sigs, proof, new bytes32[](0), rootHash, bytes32(0));

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash2, 0), 0);
    }

    function testFuzz_validateMerkelizedUserOp_whenThresholdIs1_RevertsWhen_InvalidProof(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2
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
        proof[0] = hash1;

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(sigs, proof, new bytes32[](0), rootHash, bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(InvalidMerkleProof.selector));
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(userOp, hash1, 0);
    }

    function testFuzz_validateMultiUserOp_whenThresholdIs2(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        bytes32[] memory lightProof = new bytes32[](1);
        lightProof[0] = lightHash2;

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(sigs, proof, lightProof, rootHash, lightRootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;
        lightProof[0] = lightHash1;

        userOp = _userOp2;
        userOp.signature = getRootSignature(sigs, proof, lightProof, rootHash, lightRootHash);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash2, 0), 0);
    }

    function testFuzz_validateMultiUserOp_whenThresholdIs2_RevertsWhen_InvalidProofLight(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        bytes32[] memory lightProof = new bytes32[](1);
        lightProof[0] = lightHash1;

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(sigs, proof, lightProof, rootHash, lightRootHash);

        vm.expectRevert(abi.encodeWithSelector(InvalidMerkleProof.selector));
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(userOp, hash1, 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                   VALIDATE USER OP WITH LIGHT STATE SYNC                   */
    /* -------------------------------------------------------------------------- */

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_badLightSyncSignature(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund,
        bytes calldata _sig
    )
        public
    {
        bytes32 hash = getUserOpHash(_userOp);

        bytes memory sig = abi.encode(SmartVault.Signature(SmartVault.SignatureType.LightSync, abi.encode(_sig)));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = sig;

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(userOp, hash, _missingAccountsFund);
    }

    function testFuzz_validateUserOpWithLightStateSync_addNewSigner(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp);
        (v, r, s) = vm.sign(CAROL.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);

        assertEq(vault.getSignerCount(), 4);
        assertEq(vault.getSignerAtIndex(3), abi.encode(CAROL.addr));
        assertEq(vault.getNonce(), 1);
    }

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_invalidNonce(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);
        (v, r, s) = vm.sign(CAROL.key, hash);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp1;
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

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_duplicateSigner(
        PackedUserOperation calldata _userOp1,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](2);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        sigs[1] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.expectRevert(
            abi.encodeWithSelector(LightSyncMultiSigner.SignerSetUpdateValidationFailed.selector, signerUpdates[0])
        );
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_missingSigners(
        PackedUserOperation calldata _userOp1,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.prank(address(vault));
        vault.updateThreshold(2);

        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOpWithLightStateSync_RevertsWhen_incorrectSigner(
        PackedUserOperation calldata _userOp1,
        uint256 _missingAccountsFund
    )
        public
    {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        vm.deal(address(vault), _missingAccountsFund);

        hash = getUserOpHash(_userOp1);

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature = getRootSignature(signerUpdates, sigs);

        vm.expectRevert(
            abi.encodeWithSelector(LightSyncMultiSigner.SignerSetUpdateValidationFailed.selector, signerUpdates[0])
        );
        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
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

    function testFuzz_erc1271_RevertsWhen_MerkelizedUserOp(bytes32 _hash) public {
        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(
            _hash, getRootSignature(sigs, new bytes32[](0), new bytes32[](0), bytes32(0), bytes32(0))
        );
    }

    function testFuzz_erc1271_WithLightSync_addNewSigner(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_WithLightSync_RevertsWhen_signerNotPresent(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(4), abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(SignerNotPresent.selector, 4));
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs));
    }

    function testFuzz_erc1271_WithLightSync_addNewSigner_RevertsWhen_signerAlreadyAdded(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](2);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        hash = keccak256(abi.encode(1, address(vault), newSigner));
        (v, r, s) = vm.sign(ALICE.key, hash);

        sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        signerUpdates[1] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(SignerAlreadyPresent.selector, 3));
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs));
    }

    function testFuzz_erc1271_WithLightSync_addNewSigner_alreadyInStorage(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(0));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertFalse(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_WithLightSync_addNewSigner_passkey(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(passkeyOwner, uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(vault.replaySafeHash(_hash));
        (r, s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(
            3,
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

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
    }

    function testFuzz_erc1271_WithLightSync_RevertsWhen_invalidNonce(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(1, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](1);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        (v, r, s) = vm.sign(CAROL.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));

        vm.expectRevert(
            abi.encodeWithSelector(LightSyncMultiSigner.SignerSetUpdateValidationFailed.selector, signerUpdates[0])
        );
        vm.prank(ENTRY_POINT);
        vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs));
    }

    function testFuzz_erc1271_WithLightSync_add2NewSigners(bytes32 _hash) public {
        bytes memory newSigner = abi.encode(abi.encode(CAROL.addr), uint8(3));

        bytes32 hash = keccak256(abi.encode(0, address(vault), newSigner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, hash);

        MultiSignerSignatureLib.SignatureWrapper[] memory sigs = new MultiSignerSignatureLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        LightSyncMultiSigner.SignerSetUpdate[] memory signerUpdates = new LightSyncMultiSigner.SignerSetUpdate[](2);
        signerUpdates[0] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        newSigner = abi.encode(passkeyOwner, uint8(4));

        hash = keccak256(abi.encode(1, address(vault), newSigner));
        (v, r, s) = vm.sign(CAROL.key, hash);

        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(uint8(3), abi.encodePacked(r, s, v));
        signerUpdates[1] = LightSyncMultiSigner.SignerSetUpdate(newSigner, abi.encode(sigs));

        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(vault.replaySafeHash(_hash));
        (r, s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        sigs[0] = MultiSignerSignatureLib.SignatureWrapper(
            4,
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

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getRootSignature(signerUpdates, sigs)) == 0x1626ba7e);
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
        vm.expectRevert(OnlySelf.selector);
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

    function testFuzz_addSigner_RevertWhen_callerNotAccount(bytes memory _signer, address _caller) public {
        vm.assume(_caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelf.selector);
        vault.addSigner(_signer, 0);
        vm.stopPrank();
    }

    function testFuzz_removeSigner_RevertWhen_callerNotAccount(uint8 _index, address _caller) public {
        vm.assume(_caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelf.selector);
        vault.removeSigner(_index);
        vm.stopPrank();
    }

    function testFuzz_updateThreshold_RevertWhen_callerNotAccount(uint8 _threshold, address _caller) public {
        vm.assume(_caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelf.selector);
        vault.updateThreshold(_threshold);
        vm.stopPrank();
    }

    function testFuzz_setNonce_RevertWhen_callerNotAccount(uint8 _nonce, address _caller) public {
        vm.assume(_caller != address(vault));

        vm.startPrank(_caller);
        vm.expectRevert(OnlySelf.selector);
        vault.setNonce(_nonce);
        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*                              FALLBACK MANAGER                              */
    /* -------------------------------------------------------------------------- */

    function testFuzz_setFallbackHandler(bytes4 sig_, address handler_) public {
        vm.expectEmit();
        emit UpdatedFallbackHandler(sig_, handler_);
        vm.prank(address(vault));
        vault.setFallbackHandler(sig_, handler_);

        assertEq(vault.getFallbackHandler(sig_), handler_);
    }

    function testFuzz_setFallbackHandler_RevertsWhen_callerNotSelf(
        bytes4 sig_,
        address handler_,
        address caller_
    )
        public
    {
        vm.assume(caller_ != address(vault));

        vm.expectRevert(OnlySelf.selector);
        vm.prank(caller_);
        vault.setFallbackHandler(sig_, handler_);
    }

    function testFuzz_FallbackHandler_receiveNFT(uint256 id_) public {
        nft.mint(ALICE.addr, id_);

        vm.prank(ALICE.addr);
        nft.safeTransferFrom(ALICE.addr, address(vault), id_);

        assertEq(nft.balanceOf(address(vault)), 1);
    }

    function testFuzz_FallbackHandler_RevertsWhen_receivingERC7211(address from_, uint256 tokenId_) public {
        MockERC7211 erc7211 = new MockERC7211();

        vm.expectRevert(
            abi.encodeWithSelector(FunctionNotSupported.selector, IERC7211Receiver.onERC7211Received.selector)
        );
        erc7211.transfer(from_, address(vault), tokenId_);
    }

    function testFuzz_FallbackHandler_receiveERC7211(address from_, uint256 tokenId_) public {
        MockERC7211 erc7211 = new MockERC7211();

        address fallbackHandler = address(new ERC7211FallbackHandler());

        vm.prank(address(vault));
        vault.setFallbackHandler(IERC7211Receiver.onERC7211Received.selector, fallbackHandler);

        erc7211.transfer(from_, address(vault), tokenId_);
    }

    function testFuzz_FallbackHandler_receiveEth(address sender_, uint256 amount_) public {
        vm.deal(sender_, amount_);

        vm.expectEmit();
        emit ReceiveEth(sender_, amount_);
        vm.prank(sender_);
        payable(address(vault)).call{ value: amount_ }("");
    }
}
