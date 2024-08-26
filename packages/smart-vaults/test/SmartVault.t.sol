// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest, createSigner, createSigner } from "./Base.t.sol";
import "@web-authn/../test/Utils.sol";
import "@web-authn/WebAuthn.sol";
import { FCL_Elliptic_ZZ } from "FreshCryptoLib/FCL_elliptic.sol";

import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";
import { UserOperationLib } from "src/library/UserOperationLib.sol";
import { MultiSignerLib } from "src/signers/MultiSigner.sol";

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { MultiSignerAuth } from "src/utils/MultiSignerAuth.sol";

import { Caller } from "src/utils/Caller.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

import { MockERC721 } from "./mocks/MockERC721.sol";
import { console } from "forge-std/console.sol";

import { ERC7211FallbackHandler, IERC7211Receiver, MockERC7211 } from "./mocks/MockERC7211.sol";
import { MockTransferOperator } from "./mocks/MockTransferOperator.sol";
import { Signer } from "src/signers/Signer.sol";

contract SmartVaultTest is BaseTest {
    using UserOperationLib for PackedUserOperation;

    Signer[] signers;

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

    Signer passkey;

    error OnlyEntryPoint();
    error OnlyFactory();
    error OnlySelf();
    error Unauthorized();
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);
    error InvalidNumberOfSigners();
    error InvalidThreshold();
    error InvalidMerkleProof();
    error FunctionNotSupported(bytes4 sig);
    error InvalidGasLimits();
    error InvalidPaymasterData();
    error DuplicateSigner(uint8 index);

    event UpdatedFallbackHandler(bytes4 indexed sig, address indexed handler);
    event ReceiveEth(address indexed sender, uint256 amount);

    MockERC721 nft;

    function setUp() public override {
        super.setUp();

        root = ALICE.addr;

        MIKE = PublicKey({ x: 1, y: 2 });

        (bytes32 x, bytes32 y) = abi.decode(passkeyOwner, (bytes32, bytes32));
        passkey = Signer(x, y);

        signers.push(createSigner(ALICE.addr));
        signers.push(createSigner(BOB.addr));
        signers.push(passkey);

        vault = smartVaultFactory.createAccount(root, signers, 1, 0);

        nft = new MockERC721();
    }

    function getUserOpHash(PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), ENTRY_POINT, block.chainid));
    }

    function getLightUserOpHash(PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hashLight(), getGasLimits(userOp), ENTRY_POINT, block.chainid));
    }

    function getLightUserOpHash(
        PackedUserOperation calldata userOp,
        address paymaster,
        uint256 validationGasLimit,
        uint256 postOpGasLimit
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                userOp.hashLight(),
                getGasLimits(userOp, paymaster, validationGasLimit, postOpGasLimit),
                ENTRY_POINT,
                block.chainid
            )
        );
    }

    function getMaxFee(PackedUserOperation memory userOp) internal pure returns (uint256) {
        (uint256 maxPriorityFeePerGas,) = UserOperationLib.unpackUints(userOp.gasFees);
        return maxPriorityFeePerGas;
    }

    function getGasLimit(PackedUserOperation memory userOp) internal pure returns (uint256) {
        (, uint256 gasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        return gasLimit;
    }

    function getVerificationGasLimit(PackedUserOperation memory userOp) internal pure returns (uint256) {
        (uint256 gasLimit,) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        return gasLimit;
    }

    function getGasLimits(PackedUserOperation memory userOp)
        internal
        pure
        returns (SmartVault.LightUserOpGasLimits memory)
    {
        return SmartVault.LightUserOpGasLimits(
            getMaxFee(userOp),
            userOp.preVerificationGas,
            getGasLimit(userOp),
            getVerificationGasLimit(userOp),
            address(0),
            0,
            0
        );
    }

    function getGasLimits(
        PackedUserOperation memory userOp,
        address paymaster,
        uint256 validationGasLimit,
        uint256 postOpGasLimit
    )
        internal
        pure
        returns (SmartVault.LightUserOpGasLimits memory)
    {
        return SmartVault.LightUserOpGasLimits(
            getMaxFee(userOp),
            userOp.preVerificationGas,
            getGasLimit(userOp),
            getVerificationGasLimit(userOp),
            paymaster,
            validationGasLimit,
            postOpGasLimit
        );
    }

    function getERC1271Signature(MultiSignerLib.SignatureWrapper[] memory sigs) internal pure returns (bytes memory) {
        SmartVault.ERC1271Signature memory sig = SmartVault.ERC1271Signature(sigs);
        return abi.encode(sig);
    }

    function getUserOpSignature(
        SmartVault.LightUserOpGasLimits memory gasLimits,
        MultiSignerLib.SignatureWrapper[] memory sigs
    )
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.SingleUserOpSignature memory sig = SmartVault.SingleUserOpSignature(gasLimits, sigs);
        bytes memory signature = abi.encode(sig);
        bytes1 sigType = bytes1(uint8(SmartVault.SignatureTypes.SingleUserOp));
        return bytes.concat(sigType, signature);
    }

    function getUserOpSignature(
        SmartVault.LightUserOpGasLimits memory gasLimits,
        MultiSignerLib.SignatureWrapper[] memory sigs,
        bytes32[] memory proof,
        bytes32[] memory lightProof,
        bytes32 rootHash,
        bytes32 lightRootHash
    )
        internal
        pure
        returns (bytes memory)
    {
        SmartVault.MerkelizedUserOpSignature memory sig =
            SmartVault.MerkelizedUserOpSignature(gasLimits, lightRootHash, lightProof, rootHash, proof, sigs);

        bytes memory signature = abi.encode(sig);
        bytes1 sigType = bytes1(uint8(SmartVault.SignatureTypes.MerkelizedUserOp));
        return bytes.concat(sigType, signature);
    }

    function packUints(uint256 high128, uint256 low128) internal pure returns (bytes32 packed) {
        require(high128 <= type(uint128).max, "high128 exceeds 128 bits");
        require(low128 <= type(uint128).max, "low128 exceeds 128 bits");

        packed = bytes32(uint256(high128) << 128 | low128);
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

    function packPaymasterStaticFields(
        address paymaster,
        uint256 validationGasLimit,
        uint256 postOpGasLimit
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(paymaster, uint128(validationGasLimit), uint128(postOpGasLimit));
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
        vm.expectRevert(abi.encodeWithSelector(InvalidThreshold.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, new Signer[](0), 1);
    }

    function test_initialize_RevertsWhen_signersIsGreaterThan255() public {
        vm.expectRevert(abi.encodeWithSelector(InvalidNumberOfSigners.selector));
        vm.prank(address(smartVaultFactory));
        vault.initialize(root, new Signer[](256), 1);
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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(userOp), sigs);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(
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
        userOp.signature = getUserOpSignature(getGasLimits(userOp), sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_singlePasskey_dummySignature(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(hash);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(
            2,
            abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: (FCL_Elliptic_ZZ.n / 2) - 1,
                    s: (FCL_Elliptic_ZZ.n / 2) - 1
                })
            )
        );

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(userOp), sigs);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_RevertsWhen_emptySignatures(
        PackedUserOperation memory _userOp,
        bytes32 _hash,
        uint256 _missingAccountsFund
    )
        public
    {
        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](0);
        _userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        _userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        _userOp.paymasterAndData = new bytes(0);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(DuplicateSigner.selector, 0));
        vault.validateUserOp(userOp, hash, _missingAccountsFund);
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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));
        PackedUserOperation memory userOp = _userOp;

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(DuplicateSigner.selector, 1));
        vault.validateUserOp(userOp, hash, _missingAccountsFund);
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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, _hash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, hash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(ALICE.key, lightHash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp;
        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 1);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_userOpMaxGasPriceGreater(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(_userOp.gasFees);

        vm.assume(uint128(maxPriorityFeePerGas) < type(uint128).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        PackedUserOperation memory userOp = _userOp;
        userOp.gasFees = packUints(maxPriorityFeePerGas + 1, maxFeePerGas);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidGasLimits.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_userOpCallGasLimitIsGreater(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint256 verificationGasLimit, uint256 callGasLimit) = UserOperationLib.unpackUints(_userOp.accountGasLimits);

        vm.assume(uint128(callGasLimit) < type(uint128).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        PackedUserOperation memory userOp = _userOp;
        userOp.accountGasLimits = packUints(verificationGasLimit, callGasLimit + 1);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidGasLimits.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_paymasterIsDifferent(
        PackedUserOperation calldata _userOp,
        address _paymaster,
        uint256 _validationGasLimit,
        uint256 _postOpGasLimit,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp, _paymaster, _validationGasLimit, _postOpGasLimit);

        PackedUserOperation memory userOp = _userOp;
        userOp.paymasterAndData = packPaymasterStaticFields(address(1), _validationGasLimit, _postOpGasLimit);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidPaymasterData.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_paymasterValidationLimitBreached(
        PackedUserOperation calldata _userOp,
        address _paymaster,
        uint256 _validationGasLimit,
        uint256 _postOpGasLimit,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.assume(uint128(_validationGasLimit) < type(uint128).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp, _paymaster, _validationGasLimit, _postOpGasLimit);

        PackedUserOperation memory userOp = _userOp;
        userOp.paymasterAndData = packPaymasterStaticFields(_paymaster, _validationGasLimit + 1, _postOpGasLimit);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidPaymasterData.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_paymasterPostOpGasLimitBreached(
        PackedUserOperation calldata _userOp,
        address _paymaster,
        uint256 _validationGasLimit,
        uint256 _postOpGasLimit,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.assume(uint128(_postOpGasLimit) < type(uint128).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp, _paymaster, _validationGasLimit, _postOpGasLimit);

        PackedUserOperation memory userOp = _userOp;
        userOp.paymasterAndData = packPaymasterStaticFields(_paymaster, _validationGasLimit, _postOpGasLimit + 1);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidPaymasterData.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_RevertsWhen_preVerificationGasIsGreater(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        vm.assume(_userOp.preVerificationGas < type(uint256).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        PackedUserOperation memory userOp = _userOp;
        userOp.preVerificationGas += 1;

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(_userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(address(vault));
        vault.updateThreshold(2);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidGasLimits.selector));
        assertEq(vault.validateUserOp(userOp, hash, _missingAccountsFund), 0);
    }

    function testFuzz_validateUserOp_singleUserOp_multipleEOA_userOpMaxGasIncorrect(
        PackedUserOperation calldata _userOp,
        uint256 _missingAccountsFund
    )
        public
    {
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(_userOp.gasFees);

        vm.assume(uint128(maxPriorityFeePerGas) < type(uint128).max);
        vm.deal(address(vault), _missingAccountsFund);

        bytes32 hash = getUserOpHash(_userOp);
        bytes32 lightHash = getLightUserOpHash(_userOp);

        PackedUserOperation memory userOp = _userOp;
        userOp.gasFees = packUints(maxPriorityFeePerGas + 1, maxFeePerGas);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, hash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        userOp.signature = getUserOpSignature(getGasLimits(userOp), sigs);
        userOp.paymasterAndData = new bytes(0);

        vm.prank(address(vault));
        vault.updateThreshold(2);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash2;

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature =
            getUserOpSignature(getGasLimits(_userOp1), sigs, proof, new bytes32[](0), rootHash, bytes32(0));
        userOp.paymasterAndData = new bytes(0);

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);

        proof[0] = hash1;

        userOp = _userOp2;
        userOp.signature =
            getUserOpSignature(getGasLimits(_userOp2), sigs, proof, new bytes32[](0), rootHash, bytes32(0));
        userOp.paymasterAndData = new bytes(0);
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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = hash1;

        PackedUserOperation memory userOp = _userOp1;
        userOp.signature =
            getUserOpSignature(getGasLimits(_userOp1), sigs, proof, new bytes32[](0), rootHash, bytes32(0));
        userOp.paymasterAndData = new bytes(0);

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));
        PackedUserOperation memory userOp = _userOp1;
        bytes32[] memory proof = new bytes32[](1);
        bytes32[] memory lightProof = new bytes32[](1);
        {
            proof[0] = hash2;

            lightProof[0] = lightHash2;

            userOp.signature =
                getUserOpSignature(getGasLimits(userOp), sigs, proof, lightProof, rootHash, lightRootHash);
            userOp.paymasterAndData = new bytes(0);
        }

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(userOp, hash1, 0), 0);
        {
            proof[0] = hash1;
            lightProof[0] = lightHash1;

            userOp = _userOp2;
            userOp.signature =
                getUserOpSignature(getGasLimits(userOp), sigs, proof, lightProof, rootHash, lightRootHash);
            userOp.paymasterAndData = new bytes(0);
        }

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

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));

        PackedUserOperation memory userOp = _userOp1;
        {
            bytes32[] memory proof = new bytes32[](1);
            proof[0] = hash2;

            bytes32[] memory lightProof = new bytes32[](1);
            lightProof[0] = lightHash1;

            userOp.signature =
                getUserOpSignature(getGasLimits(userOp), sigs, proof, lightProof, rootHash, lightRootHash);
            userOp.paymasterAndData = new bytes(0);
        }

        vm.expectRevert(abi.encodeWithSelector(InvalidMerkleProof.selector));
        vm.prank(ENTRY_POINT);
        vault.validateUserOp(userOp, hash1, 0);
    }

    function testFuzz_validateMultiUserOp_whenThresholdIs2_RevertsWhen_InvalidGasPrice(
        PackedUserOperation calldata _userOp1,
        PackedUserOperation calldata _userOp2
    )
        public
    {
        (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = UserOperationLib.unpackUints(_userOp1.gasFees);
        vm.assume(uint128(maxPriorityFeePerGas) < type(uint128).max);
        vm.prank(address(vault));
        vault.updateThreshold(2);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);

        bytes32 hash1 = getUserOpHash(_userOp1);
        bytes32 hash2 = getUserOpHash(_userOp2);

        bytes32 lightHash1 = getLightUserOpHash(_userOp1);
        bytes32 lightHash2 = getLightUserOpHash(_userOp2);

        bytes32 rootHash = hashPair(hash1, hash2);
        bytes32 lightRootHash = hashPair(lightHash1, lightHash2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, lightRootHash);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(BOB.key, rootHash);
        sigs[1] = MultiSignerLib.SignatureWrapper(uint8(1), abi.encodePacked(r, s, v));
        PackedUserOperation memory userOp = _userOp1;
        bytes32[] memory proof = new bytes32[](1);
        bytes32[] memory lightProof = new bytes32[](1);
        {
            proof[0] = hash2;

            lightProof[0] = lightHash2;
            userOp.signature =
                getUserOpSignature(getGasLimits(userOp), sigs, proof, lightProof, rootHash, lightRootHash);
            userOp.paymasterAndData = new bytes(0);
        }

        userOp.gasFees = packUints(maxPriorityFeePerGas + 1, maxFeePerGas);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(InvalidGasLimits.selector));
        vault.validateUserOp(userOp, hash1, 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERC1271                                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_erc1271(bytes32 _hash) public {
        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, vault.replaySafeHash(_hash));
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        vm.prank(ENTRY_POINT);
        assertTrue(vault.isValidSignature(_hash, getERC1271Signature(sigs)) == 0x1626ba7e);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EXECUTE                                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_execute(address target, uint256 value, bool _root) public {
        vm.assume(target.code.length == 0);
        assumeNotPrecompile(target);
        vm.deal(address(vault), value);

        vm.prank(_root ? root : ENTRY_POINT);
        vault.execute(Caller.Call(target, value, "0x"));
    }

    function testFuzz_execute_revertsWhenNotRootOrEntryPoint(address target, uint256 value, bytes memory data) public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector));
        vault.execute(Caller.Call(target, value, data));
    }

    function testFuzz_execute_revertsWhenBadCall(address target, uint256 value, bytes memory data) public {
        vm.assume(target.code.length == 0 && value > 0);
        vm.expectRevert();
        vm.prank(ENTRY_POINT);
        vault.execute(Caller.Call(target, value, data));
    }

    /* -------------------------------------------------------------------------- */
    /*                                EXECUTE BATCH                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_executeBatch(address target, uint256 value, bool _root) public {
        vm.assume(target.code.length == 0);
        assumeNotPrecompile(target);
        vm.deal(address(vault), value);

        Caller.Call[] memory calls = new Caller.Call[](1);
        calls[0] = Caller.Call(target, value, "0x");

        vm.prank(_root ? root : ENTRY_POINT);
        vault.executeBatch(calls);
    }

    function test_executeBatch_revertsWhenNotRootOrEntryPoint() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector));
        vault.executeBatch(new Caller.Call[](0));
    }

    function testFuzz_executeBatch_revertsWhenBadCall(address target, uint256 value, bytes memory data) public {
        vm.assume(target.code.length == 0 && value > 0);
        vm.expectRevert();

        Caller.Call[] memory calls = new Caller.Call[](1);
        calls[0] = Caller.Call(target, value, data);

        vm.prank(ENTRY_POINT);
        vault.executeBatch(calls);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   CREATE                                   */
    /* -------------------------------------------------------------------------- */

    function test_deployCreate() public {
        vm.prank(ENTRY_POINT);
        vault.execute(
            Caller.Call(
                address(vault),
                0,
                abi.encodeWithSelector(
                    SmartVault.deployCreate.selector, abi.encodePacked(type(SmartVault).creationCode, abi.encode(root))
                )
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

    function test_transferOwnership_when_ownerIsZero() public {
        vm.prank(vault.owner());
        vault.renounceOwnership();

        Caller.Call memory call =
            Caller.Call(address(vault), 0, abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr));

        vm.prank(ENTRY_POINT);
        vault.execute(call);

        assertEq(vault.owner(), BOB.addr);
    }

    /* -------------------------------------------------------------------------- */
    /*                             SIGNER SET UPDATES                             */
    /* -------------------------------------------------------------------------- */

    function testFuzz_addSigner_RevertWhen_callerNotAccount(Signer calldata _signer, address _caller) public {
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

    /* -------------------------------------------------------------------------- */
    /*                              FALLBACK MANAGER                              */
    /* -------------------------------------------------------------------------- */

    function testFuzz_setFallbackHandler(bytes4 sig_, address handler_) public {
        vm.expectEmit();
        emit UpdatedFallbackHandler(sig_, handler_);
        vm.prank(address(vault));
        vault.updateFallbackHandler(sig_, handler_);

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
        vault.updateFallbackHandler(sig_, handler_);
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
        vault.updateFallbackHandler(IERC7211Receiver.onERC7211Received.selector, fallbackHandler);

        erc7211.transfer(from_, address(vault), tokenId_);
    }

    function testFuzz_FallbackHandler_RevertsWhen_receivingERC7211HandlerCorrupt(
        address from_,
        uint256 tokenId_
    )
        public
    {
        MockERC7211 erc7211 = new MockERC7211();

        address fallbackHandler = address(this);
        vm.prank(address(vault));
        vault.updateFallbackHandler(IERC7211Receiver.onERC7211Received.selector, fallbackHandler);

        vm.expectRevert();
        erc7211.transfer(from_, address(vault), tokenId_);
    }

    function testFuzz_FallbackHandler_receiveEth(address sender_, uint256 amount_) public {
        vm.deal(sender_, amount_);

        vm.expectEmit();
        emit ReceiveEth(sender_, amount_);
        vm.prank(sender_);
        (bool ok,) = payable(address(vault)).call{ value: amount_ }("");
        require(ok);
    }

    /* -------------------------------------------------------------------------- */
    /*                              Module MANAGER                                */
    /* -------------------------------------------------------------------------- */

    event EnabledModule(address indexed module);
    event DisabledModule(address indexed module);
    event ExecutedTxFromModule(address indexed module, SmartVault.Call call);
    event AccountAdded(address account);
    event AccountRemoved(address account);

    error OnlyModule();

    function testFuzz_OperatorManager_enableModule(address module_) public {
        vm.expectEmit();
        emit EnabledModule(module_);
        vm.prank(address(vault));
        vault.enableModule(module_);

        assertTrue(vault.isModuleEnabled(module_));
    }

    function testFuzz_OperatorManager_enableModule_RevertsWhen_callerNotSelf(address module_, address caller_) public {
        vm.assume(caller_ != address(vault));

        vm.expectRevert(OnlySelf.selector);
        vm.prank(caller_);
        vault.enableModule(module_);
    }

    function test_OperatorManager_setupAndEnableModule() public {
        MockTransferOperator module = new MockTransferOperator();
        bytes memory data = abi.encodeWithSelector(MockTransferOperator.addAccount.selector);

        vm.expectEmit();
        emit EnabledModule(address(module));
        emit AccountAdded(address(vault));
        vm.prank(address(vault));
        vault.setupAndEnableModule(address(module), address(module), data);

        assertTrue(vault.isModuleEnabled(address(module)));
    }

    function testFuzz_OperatorManager_setupAndEnableModule_RevertsWhen_callerNotSelf(
        address caller_,
        address module_,
        address setupContract_,
        bytes memory data_
    )
        public
    {
        vm.assume(caller_ != address(vault));

        vm.expectRevert(OnlySelf.selector);
        vm.prank(caller_);
        vault.setupAndEnableModule(module_, setupContract_, data_);
    }

    function testFuzz_OperatorManager_disableModule(address module_) public {
        testFuzz_OperatorManager_enableModule(module_);

        vm.expectEmit();
        emit DisabledModule(module_);
        vm.prank(address(vault));
        vault.disableModule(module_);

        assertFalse(vault.isModuleEnabled(module_));
    }

    function test_OperatorManager_teardownAndDisableModule() public {
        MockTransferOperator module = new MockTransferOperator();
        bytes memory data = abi.encodeWithSelector(MockTransferOperator.removeAccount.selector);

        vm.expectEmit();
        emit DisabledModule(address(module));
        emit AccountRemoved(address(vault));
        vm.prank(address(vault));
        vault.teardownAndDisableModule(address(module), address(module), data);

        assertFalse(vault.isModuleEnabled(address(module)));
    }

    function testFuzz_OperatorManager_teardownAndDisableModule_RevertsWhen_callerNotSelf(
        address caller_,
        address module_,
        address teardownContract_,
        bytes memory data_
    )
        public
    {
        vm.assume(caller_ != address(vault));

        vm.expectRevert(OnlySelf.selector);
        vm.prank(caller_);
        vault.teardownAndDisableModule(module_, teardownContract_, data_);
    }

    function testFuzz_OperatorManager_disableModule_RevertsWhen_callerNotSelf(
        address module_,
        address caller_
    )
        public
    {
        vm.assume(caller_ != address(vault));

        vm.expectRevert(OnlySelf.selector);
        vm.prank(caller_);
        vault.disableModule(module_);
    }

    function testFuzz_OperatorManager_executeFromModuleSingle(address to_, uint256 amount_) public {
        assumeAddressIsNot(to_, AddressType.NonPayable);
        vm.assume(to_ != address(vault));

        vm.assume(amount_ > 0);
        vm.deal(address(vault), amount_);

        MockTransferOperator module = new MockTransferOperator();

        vm.prank(address(vault));
        vault.enableModule(address(module));

        assertEq(address(vault).balance, amount_);

        bytes memory data;
        Caller.Call memory call = Caller.Call(to_, amount_, data);

        vm.expectEmit();
        emit ExecutedTxFromModule(address(module), call);
        module.transfer(vault, amount_, to_);

        assertEq(address(vault).balance, 0);
    }

    function testFuzz_OperatorManager_executeFromModuleSingle_RevertsWhen_callerNotOperator(
        address caller_,
        Caller.Call memory call_
    )
        public
    {
        vm.expectRevert(OnlyModule.selector);
        vm.prank(caller_);
        vault.executeFromModule(call_);
    }

    function testFuzz_OperatorManager_executeFromModuleBatch(address to_, uint96 amount_) public {
        assumeAddressIsNot(to_, AddressType.NonPayable);
        vm.assume(to_ != address(vault));

        vm.assume(amount_ > 0);
        vm.deal(address(vault), amount_ * uint256(2));

        MockTransferOperator module = new MockTransferOperator();

        vm.prank(address(vault));
        vault.enableModule(address(module));

        assertGt(address(vault).balance, 0);

        bytes memory data;
        Caller.Call memory call = Caller.Call(to_, amount_, data);
        vm.expectEmit();
        emit ExecutedTxFromModule(address(module), call);
        emit ExecutedTxFromModule(address(module), call);
        module.transfer(vault, amount_, to_, amount_, to_);

        assertEq(address(vault).balance, 0);
    }

    function testFuzz_OperatorManager_executeFromModuleBatch_RevertsWhen_callerNotOperator(
        address caller_,
        Caller.Call[] memory calls_
    )
        public
    {
        vm.expectRevert(OnlyModule.selector);
        vm.prank(caller_);
        vault.executeFromModule(calls_);
    }

    /* -------------------------------------------------------------------------- */
    /*                               ONLY SELF TESTS                              */
    /* -------------------------------------------------------------------------- */

    function test_onlySelf_addSigner() public {
        Caller.Call memory call = Caller.Call(
            address(vault), 0, abi.encodeWithSelector(MultiSignerAuth.addSigner.selector, createSigner(BOB.addr), 4)
        );

        vm.prank(ENTRY_POINT);
        vault.execute(call);

        assertEq(vault.getSigner(4), createSigner(BOB.addr));
        assertEq(vault.getSignerCount(), 4);
    }

    function test_onlySelf_removeSigner() public {
        Caller.Call memory call =
            Caller.Call(address(vault), 0, abi.encodeWithSelector(MultiSignerAuth.removeSigner.selector, 0));

        vm.prank(ENTRY_POINT);
        vault.execute(call);

        assertEq(vault.getSigner(0), createSigner(address(0)));
        assertEq(vault.getSignerCount(), 2);
    }

    function test_onlySelf_updateThreshold() public {
        Caller.Call memory call =
            Caller.Call(address(vault), 0, abi.encodeWithSelector(MultiSignerAuth.updateThreshold.selector, 2));

        vm.prank(ENTRY_POINT);
        vault.execute(call);

        assertEq(vault.getThreshold(), 2);
    }

    function test_onlySelf_upgradeImplementation_when_ownerIsZero() public {
        vm.prank(vault.owner());
        vault.renounceOwnership();

        address newImplementation = address(new SmartVault());
        Caller.Call memory call = Caller.Call(
            address(vault),
            0,
            abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, newImplementation, new bytes(0))
        );

        vm.prank(ENTRY_POINT);
        vault.execute(call);

        assertEq(vault.getImplementation(), newImplementation);
    }

    function test_onlySelf_upgradeImplementation_revertsWhen_ownerIsNotZero() public {
        address newImplementation = address(new SmartVault());
        Caller.Call memory call = Caller.Call(
            address(vault),
            0,
            abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, newImplementation, new bytes(0))
        );

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector));
        vault.execute(call);
    }
}
