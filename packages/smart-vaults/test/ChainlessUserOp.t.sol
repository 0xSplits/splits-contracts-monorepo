// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest, createSigner } from "./Base.t.sol";

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

import { MultiSignerLib } from "src/signers/MultiSigner.sol";
import { Signer } from "src/signers/Signer.sol";
import { Caller } from "src/utils/Caller.sol";
import { MultiSignerAuth } from "src/utils/MultiSignerAuth.sol";
import { SmartVault } from "src/vault/SmartVault.sol";

import { console2 } from "forge-std/console2.sol";

/// @notice Spike tests: one signature validates and executes a state update on any chain.
contract ChainlessUserOpTest is BaseTest {
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    bytes32 constant CTX_SLOT = 0xa376dc2f3bf9f2889ab135e26e6fcd0514f9576ec68e5f2a682d95ca957ade32;

    uint256 constant CHAIN_A = 31_337;
    uint256 constant CHAIN_B = 8453;

    EntryPoint entryPoint;

    /// @dev 2-of-2 vault (ALICE, BOB), owned by CAROL's EOA.
    SmartVault vault;

    /// @dev 1-of-1 vault (CAROL) acting as owner of `ownedVault` — the recovery composition.
    SmartVault ownerVault;
    SmartVault ownedVault;

    function setUp() public override {
        super.setUp();

        EntryPoint deployed = new EntryPoint();
        vm.etch(ENTRY_POINT, address(deployed).code);
        entryPoint = EntryPoint(payable(ENTRY_POINT));

        Signer[] memory signers = new Signer[](2);
        signers[0] = createSigner(ALICE.addr);
        signers[1] = createSigner(BOB.addr);
        vault = smartVaultFactory.createAccount(CAROL.addr, signers, 2, 0);

        Signer[] memory ownerSigners = new Signer[](1);
        ownerSigners[0] = createSigner(CAROL.addr);
        ownerVault = smartVaultFactory.createAccount(CAROL.addr, ownerSigners, 1, 1);

        Signer[] memory ownedSigners = new Signer[](1);
        ownedSigners[0] = createSigner(ALICE.addr);
        ownedVault = smartVaultFactory.createAccount(address(ownerVault), ownedSigners, 1, 2);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   HELPERS                                  */
    /* -------------------------------------------------------------------------- */

    function _chainlessUserOp(
        SmartVault vault_,
        uint256 chainlessNonce_,
        Caller.Call[] memory calls_
    )
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(vault_);
        op.nonce = entryPoint.getNonce(address(vault_), 0);
        op.initCode = "";
        op.callData = abi.encodeWithSelector(SmartVault.executeChainless.selector, chainlessNonce_, calls_);
        // verificationGasLimit | callGasLimit
        op.accountGasLimits = bytes32((uint256(2_000_000) << 128) | 4_000_000);
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32(0); // zero gas price: required by the chainless validation rules
        op.paymasterAndData = "";
        op.signature = "";
    }

    function _thresholdSig(
        SmartVault vault_,
        uint256 chainlessNonce_,
        bytes memory callData_,
        Account[2] memory signers_
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = vault_.getChainlessUserOpHash(chainlessNonce_, callData_);

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        for (uint256 i; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signers_[i].key, SignatureCheckerLib.toEthSignedMessageHash(hash));
            sigs[i] = MultiSignerLib.SignatureWrapper(uint8(i), abi.encodePacked(r, s, v));
        }

        return _encodeChainlessSig(SmartVault.ChainlessUserOpSignature(chainlessNonce_, false, "", sigs));
    }

    function _ownerEOASig(
        SmartVault vault_,
        uint256 chainlessNonce_,
        bytes memory callData_,
        Account memory owner_
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = vault_.getChainlessUserOpHash(chainlessNonce_, callData_);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner_.key, hash);

        return _encodeChainlessSig(
            SmartVault.ChainlessUserOpSignature(
                chainlessNonce_, true, abi.encodePacked(r, s, v), new MultiSignerLib.SignatureWrapper[](0)
            )
        );
    }

    /// @dev Owner is a vault: its signer signs the owned vault's chainless hash through the owner
    ///      vault's CHAINLESS 1271 domain. This is the recovery composition — if the owner vault
    ///      wrapped with its chain-bound domain instead, the signature would pin to one chain.
    function _ownerVaultSig(
        SmartVault vault_,
        uint256 chainlessNonce_,
        bytes memory callData_,
        SmartVault ownerVault_,
        Account memory ownerVaultSigner_
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = vault_.getChainlessUserOpHash(chainlessNonce_, callData_);
        bytes32 ownerDigest = ownerVault_.chainlessReplaySafeHash(hash);

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(ownerVaultSigner_.key, SignatureCheckerLib.toEthSignedMessageHash(ownerDigest));

        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](1);
        sigs[0] = MultiSignerLib.SignatureWrapper(uint8(0), abi.encodePacked(r, s, v));

        // 0x01 = chainless 1271 domain discriminator
        bytes memory ownerSig = abi.encodePacked(bytes1(0x01), abi.encode(SmartVault.ERC1271Signature(sigs)));

        return _encodeChainlessSig(
            SmartVault.ChainlessUserOpSignature(
                chainlessNonce_, true, ownerSig, new MultiSignerLib.SignatureWrapper[](0)
            )
        );
    }

    function _encodeChainlessSig(SmartVault.ChainlessUserOpSignature memory sig_) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(SmartVault.SignatureTypes.ChainlessUserOp)), abi.encode(sig_));
    }

    function _handleOps(PackedUserOperation memory op_) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op_;
        entryPoint.handleOps(ops, payable(DAN.addr));
    }

    function _updateSignerSetCall(
        SmartVault vault_,
        MultiSignerLib.SignerSetOp[] memory ops_,
        uint8 threshold_
    )
        internal
        pure
        returns (Caller.Call[] memory calls)
    {
        calls = new Caller.Call[](1);
        calls[0] = Caller.Call(
            address(vault_), 0, abi.encodeWithSelector(MultiSignerAuth.updateSignerSet.selector, ops_, threshold_)
        );
    }

    function _assertCtxCleared(SmartVault vault_) internal view {
        assertEq(uint256(vm.load(address(vault_), CTX_SLOT)), 0, "ctx not cleared");
    }

    /* -------------------------------------------------------------------------- */
    /*                        CROSS-CHAIN REPLAY (THE POINT)                       */
    /* -------------------------------------------------------------------------- */

    /// @notice One threshold-signed op — add DAN, raise threshold to 3 — executes identically on
    ///         two chains.
    function test_chainlessReplay_thresholdSigners_acrossChains() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 3));
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        uint256 snapshot = vm.snapshot();

        uint256 gasBefore = gasleft();
        _handleOps(op);
        console2.log("handleOps gas (threshold chainless updateSignerSet):", gasBefore - gasleft());

        assertEq(vault.getSigner(2), createSigner(DAN.addr));
        assertEq(vault.getThreshold(), 3);
        assertEq(vault.getSignerCount(), 3);
        assertEq(vault.getChainlessNonce(), 1);
        _assertCtxCleared(vault);

        // Chain B: identical bytes, fresh state, different chainId.
        vm.revertTo(snapshot);
        vm.chainId(CHAIN_B);
        assertEq(vault.getSignerCount(), 2, "snapshot revert failed");

        _handleOps(op);

        assertEq(vault.getSigner(2), createSigner(DAN.addr));
        assertEq(vault.getThreshold(), 3);
        assertEq(vault.getChainlessNonce(), 1);
        _assertCtxCleared(vault);
    }

    /// @notice The 2-of-2 signer swap that requires temp-signer gymnastics today: remove BOB and
    ///         install DAN at his slot in a single atomic call.
    function test_chainless_atomic2of2Swap() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](2);
        ops[0] = MultiSignerLib.SignerSetOp(1, Signer(0, 0)); // remove BOB
        ops[1] = MultiSignerLib.SignerSetOp(1, createSigner(DAN.addr)); // add DAN at slot 1

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 0));
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        _handleOps(op);

        assertEq(vault.getSigner(1), createSigner(DAN.addr));
        assertEq(vault.getThreshold(), 2);
        assertEq(vault.getSignerCount(), 2);
    }

    /// @notice Owner (EOA) recovers the signer set (swap both signers for DAN, threshold 1) and
    ///         hands off ownership in one chainless op, replayed on two chains.
    function test_chainlessReplay_ownerEOA_recoverAndTransferOwnership() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](3);
        ops[0] = MultiSignerLib.SignerSetOp(0, Signer(0, 0)); // remove ALICE
        ops[1] = MultiSignerLib.SignerSetOp(1, Signer(0, 0)); // remove BOB
        ops[2] = MultiSignerLib.SignerSetOp(0, createSigner(DAN.addr));

        Caller.Call[] memory calls = new Caller.Call[](2);
        calls[0] = _updateSignerSetCall(vault, ops, 1)[0];
        calls[1] = Caller.Call(address(vault), 0, abi.encodeWithSignature("transferOwnership(address)", DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, calls);
        op.signature = _ownerEOASig(vault, 0, op.callData, CAROL);

        uint256 snapshot = vm.snapshot();

        uint256 gasBefore = gasleft();
        _handleOps(op);
        console2.log("handleOps gas (owner recover via updateSignerSet + transferOwnership):", gasBefore - gasleft());

        assertEq(vault.getSigner(0), createSigner(DAN.addr));
        assertEq(vault.getSignerCount(), 1);
        assertEq(vault.getThreshold(), 1);
        assertEq(vault.owner(), DAN.addr);
        _assertCtxCleared(vault);

        vm.revertTo(snapshot);
        vm.chainId(CHAIN_B);

        _handleOps(op);

        assertEq(vault.getSigner(0), createSigner(DAN.addr));
        assertEq(vault.owner(), DAN.addr);
    }

    /// @notice The recovery composition: the owner is itself a vault, signing through its
    ///         chainless 1271 domain. One signature by the owner vault's signer swaps the owned
    ///         vault's signer on two chains.
    function test_chainlessReplay_ownerVault_chainless1271() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](2);
        ops[0] = MultiSignerLib.SignerSetOp(0, Signer(0, 0)); // remove ALICE
        ops[1] = MultiSignerLib.SignerSetOp(0, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(ownedVault, 0, _updateSignerSetCall(ownedVault, ops, 0));
        op.signature = _ownerVaultSig(ownedVault, 0, op.callData, ownerVault, CAROL);

        uint256 snapshot = vm.snapshot();

        _handleOps(op);
        assertEq(ownedVault.getSigner(0), createSigner(DAN.addr));
        assertEq(ownedVault.getSignerCount(), 1);

        vm.revertTo(snapshot);
        vm.chainId(CHAIN_B);

        _handleOps(op);
        assertEq(ownedVault.getSigner(0), createSigner(DAN.addr));
        assertEq(ownedVault.getSignerCount(), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  NEGATIVES                                 */
    /* -------------------------------------------------------------------------- */

    function test_chainless_replayOnSameChain_reverts() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 0));
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        _handleOps(op);
        assertEq(vault.getChainlessNonce(), 1);

        // Same op again on the same chain: chainless nonce already consumed.
        op.nonce = entryPoint.getNonce(address(vault), 0);
        vm.expectRevert(); // FailedOp(AA23 reverted) wrapping InvalidChainlessNonce
        _handleOps(op);
    }

    function test_chainless_outOfOrderNonce_reverts() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 1, _updateSignerSetCall(vault, ops, 0));
        op.signature = _thresholdSig(vault, 1, op.callData, [ALICE, BOB]);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(abi.encodeWithSelector(SmartVault.InvalidChainlessNonce.selector, 0, 1));
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_nonZeroGasFees_reverts() public {
        PackedUserOperation memory op = _buildValidThresholdOp();
        op.gasFees = bytes32(uint256(1));

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_paymasterSet_reverts() public {
        PackedUserOperation memory op = _buildValidThresholdOp();
        op.paymasterAndData = abi.encodePacked(address(1), uint128(1), uint128(1));

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_callDataNotExecuteChainless_reverts() public {
        PackedUserOperation memory op = _buildValidThresholdOp();
        op.callData = abi.encodeWithSelector(SmartVault.execute.selector, Caller.Call(address(vault), 0, ""));

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_externalTarget_reverts() public {
        Caller.Call[] memory calls = new Caller.Call[](1);
        calls[0] = Caller.Call(DAN.addr, 0, "");

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, calls);
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_nonZeroValue_reverts() public {
        Caller.Call[] memory calls = new Caller.Call[](1);
        calls[0] = Caller.Call(address(vault), 1, "");

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, calls);
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    function test_chainless_callDataNonceMismatch_reverts() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 5, _updateSignerSetCall(vault, ops, 0));
        // signature claims nonce 0, callData says 5
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessUserOp.selector);
        vault.validateUserOp(op, bytes32(0), 0);
    }

    /// @notice A wrong-hash signature (e.g. signed under a chain-bound scheme) fails soft with
    ///         SIG_VALIDATION_FAILED, per 4337.
    function test_chainless_wrongDomainSignature_invalid() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 0));

        // Sign the CHAIN-BOUND wrap of the chainless struct hash instead of the chainless digest.
        bytes32 wrongHash = vault.replaySafeHash(keccak256(op.callData));
        MultiSignerLib.SignatureWrapper[] memory sigs = new MultiSignerLib.SignatureWrapper[](2);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE.key, SignatureCheckerLib.toEthSignedMessageHash(wrongHash));
        sigs[0] = MultiSignerLib.SignatureWrapper(0, abi.encodePacked(r, s, v));
        (v, r, s) = vm.sign(BOB.key, SignatureCheckerLib.toEthSignedMessageHash(wrongHash));
        sigs[1] = MultiSignerLib.SignatureWrapper(1, abi.encodePacked(r, s, v));
        op.signature = _encodeChainlessSig(SmartVault.ChainlessUserOpSignature(0, false, "", sigs));

        vm.prank(ENTRY_POINT);
        assertEq(vault.validateUserOp(op, bytes32(0), 0), 1);
    }

    /// @notice Threshold signers cannot smuggle owner-only actions: validation passes (their
    ///         signature is genuine) but transferOwnership hits _checkOwner (ctx=THRESHOLD) and
    ///         the op's calls revert.
    function test_chainless_thresholdCannotTransferOwnership_roleGate() public {
        Caller.Call[] memory calls = new Caller.Call[](1);
        calls[0] = Caller.Call(address(vault), 0, abi.encodeWithSignature("transferOwnership(address)", DAN.addr));

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, calls);
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        _handleOps(op); // does not revert: the op fails post-validation, EntryPoint logs it

        // owner untouched, nonce consumed
        assertEq(vault.owner(), CAROL.addr);
        assertEq(vault.getChainlessNonce(), 1);
    }

    /// @notice executeChainless is unreachable outside a validated chainless op.
    function test_executeChainless_withoutValidation_reverts() public {
        Caller.Call[] memory calls = new Caller.Call[](0);

        vm.prank(ENTRY_POINT);
        vm.expectRevert(SmartVault.InvalidChainlessContext.selector);
        vault.executeChainless(0, calls);
    }

    /// @notice Batch invariants validated once at the end: a batch ending with threshold > count
    ///         reverts as a whole.
    function test_updateSignerSet_invalidEndState_reverts() public {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(1, Signer(0, 0)); // remove BOB -> count 1, threshold 2

        PackedUserOperation memory op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 0));
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);

        _handleOps(op); // op fails post-validation

        assertEq(vault.getSignerCount(), 2, "batch should have reverted atomically");
        assertEq(vault.getSigner(1), createSigner(BOB.addr));
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL HELPERS                              */
    /* -------------------------------------------------------------------------- */

    function _buildValidThresholdOp() internal view returns (PackedUserOperation memory op) {
        MultiSignerLib.SignerSetOp[] memory ops = new MultiSignerLib.SignerSetOp[](1);
        ops[0] = MultiSignerLib.SignerSetOp(2, createSigner(DAN.addr));

        op = _chainlessUserOp(vault, 0, _updateSignerSetCall(vault, ops, 0));
        op.signature = _thresholdSig(vault, 0, op.callData, [ALICE, BOB]);
    }
}
