// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { UserOperationLib } from "../library/UserOperationLib.sol";
import { MultiSignerLib } from "../signers/MultiSigner.sol";
import { Signer } from "../signers/Signer.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { FallbackManager } from "../utils/FallbackManager.sol";
import { ModuleManager } from "../utils/ModuleManager.sol";
import { MultiSignerAuth } from "../utils/MultiSignerAuth.sol";

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { IAccount } from "account-abstraction/interfaces/IAccount.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/**
 * @title Splits Smart Accounts/Vaults
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @dev Based on Coinbase's Smart Wallet (https://github.com/coinbase/smart-wallet) and Solady's Smart Wallet.
 */
contract SmartVault is IAccount, Ownable, UUPSUpgradeable, MultiSignerAuth, ERC1271, FallbackManager, ModuleManager {
    using UserOperationLib for PackedUserOperation;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Primary Signature types
    enum SignatureTypes {
        SingleUserOp,
        MerkelizedUserOp,
        ERC1271,
        ChainlessUserOp
    }

    /// @notice Upper limits for maxPriorityFeePerGas, preVerificationGas, verificationGasLimit, callGasLimit,
    /// paymasterVerificationGasLimit and paymasterPostOpGasLimit that should be charged by the userOp. This is included
    /// in the light userOp hash to ensure last signer does not exceed the specified gas price/limits. These values will
    /// be ignored when threshold is 1. paymaster, paymasterVerificationGasLimit and paymasterPostOpGasLimit will be
    /// ignored if paymasterAndData is empty.
    struct LightUserOpGasLimits {
        uint256 maxPriorityFeePerGas;
        uint256 preVerificationGas;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        address paymaster;
        uint256 paymasterVerificationGasLimit;
        uint256 paymasterPostOpGasLimit;
    }

    /// @notice Single User Op Signature Scheme.
    struct SingleUserOpSignature {
        /// @notice light user op gas limits.
        LightUserOpGasLimits gasLimits;
        /// @notice list of signatures where threshold - 1
        /// signatures will be verified against the light userOp hash and the final signature will be verified
        /// against the userOp hash.
        MultiSignerLib.SignatureWrapper[] signatures;
    }

    /// @notice Merkelized User Op Signature Scheme.
    struct MerkelizedUserOpSignature {
        /// @notice light user op gas limits.
        LightUserOpGasLimits gasLimits;
        /// @notice merkleRoot of all the light(userOp) in the Merkle Tree. If threshold is 1, this will be
        /// bytes32(0).
        bytes32 lightMerkleTreeRoot;
        /// @notice Proof to verify if the light userOp hash is present in the light merkle tree root. If
        /// threshold is 1, this will be empty.
        bytes32[] lightMerkleProof;
        /// @notice merkleRoot of all the user ops in the Merkle Tree.
        bytes32 merkleTreeRoot;
        /// @notice Proof to verify if the userOp hash is present in the merkle tree.
        bytes32[] merkleProof;
        /// @notice list of signatures where threshold - 1
        /// signatures will be verified against the `lightMerkleTreeRoot` and the final signature will be verified
        /// against the `merkleTreeRoot`.
        MultiSignerLib.SignatureWrapper[] signatures;
    }

    /// @notice ERC1271 Signature scheme
    struct ERC1271Signature {
        MultiSignerLib.SignatureWrapper[] signatures;
    }

    /**
     * @notice Chainless User Op Signature Scheme. Signed over the chainless hash (no chainId, no
     *         EntryPoint nonce, no gas limits, no time bounds) so one signature replays on every
     *         chain, keeping account state in lockstep.
     */
    struct ChainlessUserOpSignature {
        /// @notice The account's chainless nonce this op consumes (sequential, vault storage).
        uint256 nonce;
        /// @notice If true, `ownerSignature` is verified against `owner()`; else `signatures`
        /// against the signer set.
        bool viaOwner;
        /// @notice Owner signature over the chainless hash (ECDSA or ERC-1271, incl. 7702).
        bytes ownerSignature;
        /// @notice Threshold signatures over the chainless hash. All signers sign the same hash;
        /// no light hash exists because gas is unsigned (and unpaid).
        MultiSignerLib.SignatureWrapper[] signatures;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Splits smart vaults factory.
    address public immutable FACTORY;

    /// @notice EIP-712 typehash for the chainless userOp digest.
    bytes32 private constant _CHAINLESS_USER_OP_TYPEHASH =
        keccak256("ChainlessUserOp(uint256 nonce,bytes32 callDataHash,address entryPoint)");

    /// @dev Slot for the sequential chainless nonce: keccak256("splits.spike.chainlessNonce").
    bytes32 private constant _CHAINLESS_NONCE_SLOT = 0xbf84fbe07ee46584cb00ca9dc247f1cc834d70e536df2ef0199eff397652abeb;

    /**
     * @dev Slot for the chainless execution context: keccak256("splits.spike.chainlessCtx").
     *      Packed as `(chainlessNonce << 8) | role`. Written during validation once the chainless
     *      signature verifies, consumed and cleared by `executeChainless`. The nonce in the
     *      packing makes two chainless ops for this account in one bundle fail closed instead of
     *      leaking the second op's role to the first op's execution.
     *      ponytail: plain storage because solc is pinned to 0.8.23/shanghai — transient storage
     *      once the toolchain moves to cancun.
     */
    bytes32 private constant _CHAINLESS_CTX_SLOT = 0xa376dc2f3bf9f2889ab135e26e6fcd0514f9576ec68e5f2a682d95ca957ade32;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when caller is not entry point.
    error OnlyEntryPoint();

    /// @notice Thrown when caller is not factory.
    error OnlyFactory();

    /// @notice Thrown when caller is not address(this).
    error OnlySelf();

    /// @notice Thrown when contract creation has failed.
    error FailedContractCreation();

    /// @notice Thrown when Signature is of unknown type.
    error InvalidSignatureType();

    /// @notice Thrown when LightUserOpGasLimits have been breached.
    error InvalidGasLimits();

    /// @notice Thrown when Paymaster LightUserOpGasLimits have been breached.
    error InvalidPaymasterData();

    /// @notice Thrown when a chainless userOp violates its structural constraints (non-zero gas
    /// price, paymaster present, callData not executeChainless, call not a zero-value self-call,
    /// or nonce mismatch between callData and signature).
    error InvalidChainlessUserOp();

    /// @notice Thrown when a chainless userOp's nonce is not the account's current chainless nonce.
    error InvalidChainlessNonce(uint256 expected, uint256 actual);

    /// @notice Thrown when a signer-state function is called outside a chainless execution context
    /// carrying the required role.
    error InvalidChainlessContext();

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert OnlyEntryPoint();
        }
        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint or the owner.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) {
            _checkOwner();
        }
        _;
    }

    /// @notice Reverts when caller is not this account.
    modifier onlySelf() virtual {
        if (msg.sender != address(this)) {
            revert OnlySelf();
        }
        _;
    }

    /**
     * @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
     *
     * @dev Subclass MAY override this modifier for better funds management (e.g. send to the
     *      EntryPoint more than the minimum required, so that in future transactions it will not
     *      be required to send again).
     *
     * @param missingAccountFunds_ The minimum value this modifier should send the EntryPoint which
     *                            MAY be zero, in case there is enough deposit, or the userOp has a
     *                            paymaster.
     */
    modifier payPrefund(uint256 missingAccountFunds_) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds_ {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds_, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor() ERC1271("splitsSmartVault", "1") {
        FACTORY = msg.sender;
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initializes the account with the `signers` and `threshold`.
     *
     * @dev Reverts if caller is not factory.
     * @dev Reverts if signers or threshold is invalid.
     *
     * @param owner_ Owner of the smart account.
     * @param signers_ Array of initial signers. Each signer is of type `Signer`.
     * @param threshold_ Number of signers required to approve a signature.
     */
    function initialize(address owner_, Signer[] calldata signers_, uint8 threshold_) external payable {
        if (msg.sender != FACTORY) revert OnlyFactory();

        _initializeOwner(owner_);
        _initializeMultiSignerAuth(signers_, threshold_);
    }

    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
     *
     * @param userOp_              - The operation that is about to be executed.
     * @param userOpHash_          - Hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds_ - Missing funds on the account's deposit in the entrypoint.
     *                              This is the minimum amount to transfer to the sender(entryPoint) to be
     *                              able to make the call. The excess is left as a deposit in the entrypoint
     *                              for future calls. Can be withdrawn anytime using "entryPoint.withdrawTo()".
     *                              In case there is a paymaster in the request (or the current deposit is high
     *                              enough), this value will be zero.
     * @return validationData       - Packaged ValidationData structure. use `_packValidationData` and
     *                              `_unpackValidationData` to encode and decode.
     *                              <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *                                 otherwise, an address of an "authorizer" contract.
     *                              <6-byte> validUntil - Last timestamp this operation is valid. 0 for "indefinite"
     *                              <6-byte> validAfter - First timestamp this operation is valid
     *                                                    If an account doesn't use time-range, it is enough to
     *                                                    return SIG_VALIDATION_FAILED value (1) for signature failure.
     *                              Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp_,
        bytes32 userOpHash_,
        uint256 missingAccountFunds_
    )
        external
        onlyEntryPoint
        payPrefund(missingAccountFunds_)
        returns (uint256 validationData)
    {
        SignatureTypes signatureType = _getSignatureType(userOp_.signature[0]);
        bytes32 lightHash;

        if (signatureType == SignatureTypes.SingleUserOp) {
            SingleUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (SingleUserOpSignature));

            // if threshold is greater than 1, `threshold - 1` signers will sign over the light userOp hash. We lazily
            // calculate light userOp hash based on number of signatures. If threshold is 1 then light userOp hash
            // won't be needed.
            if (signature.signatures.length > 1) {
                _verifyGasLimits(userOp_, signature.gasLimits);
                lightHash = _getLightUserOpHash(userOp_, signature.gasLimits);
            }

            return _validateSingleUserOp(lightHash, userOpHash_, signature);
        } else if (signatureType == SignatureTypes.MerkelizedUserOp) {
            MerkelizedUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (MerkelizedUserOpSignature));

            // if threshold is greater than 1, `threshold - 1` signers will sign over the merkle tree root of light user
            // op hash(s). We lazily calculate light userOp hash based on number of signatures. If threshold
            // is 1 then light userOp hash won't be needed.
            if (signature.signatures.length > 1) {
                _verifyGasLimits(userOp_, signature.gasLimits);
                lightHash = _getLightUserOpHash(userOp_, signature.gasLimits);
            }

            return _validateMerkelizedUserOp(lightHash, userOpHash_, signature);
        } else if (signatureType == SignatureTypes.ChainlessUserOp) {
            return _validateChainlessUserOp(userOp_);
        } else {
            revert InvalidSignatureType();
        }
    }

    /**
     * @notice Executes a chainless userOp's calls. Only reachable as the callData of a validated
     *         ChainlessUserOp (enforced via the context written during validation).
     *
     * @param nonce_ The chainless nonce this op consumed; must match the stored context.
     * @param calls_ Zero-value calls to this account (enforced during validation).
     */
    function executeChainless(uint256 nonce_, Call[] calldata calls_) external payable onlyEntryPoint {
        uint256 ctx = _getChainlessCtx();
        if (ctx >> 8 != nonce_ || uint8(ctx) == 0) revert InvalidChainlessContext();

        uint256 numCalls = calls_.length;
        for (uint256 i; i < numCalls; i++) {
            _call(calls_[i]);
        }

        _setChainlessCtx(0);
    }

    /**
     * @notice Executes the given call from this account.
     *
     * @dev Can only be called by the Entrypoint or owner of this account.
     *
     * @param call_ The `Call` to execute.
     */
    function execute(Call calldata call_) external payable onlyEntryPointOrOwner {
        _call(call_);
    }

    /**
     * @notice Executes batch of `Call`s.
     *
     * @dev Can only be called by the Entrypoint or owner of this account.
     *
     * @param calls_ The list of `Call`s to execute.
     */
    function executeBatch(Call[] calldata calls_) external payable onlyEntryPointOrOwner {
        uint256 numCalls = calls_.length;
        for (uint256 i; i < numCalls; i++) {
            _call(calls_[i]);
        }
    }

    /// @notice Returns the address of the EntryPoint v0.7.
    function entryPoint() public view virtual returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    /// @notice Returns the account's current chainless nonce.
    function getChainlessNonce() public view returns (uint256 nonce) {
        assembly ("memory-safe") {
            nonce := sload(_CHAINLESS_NONCE_SLOT)
        }
    }

    /**
     * @notice Chainless userOp digest that signers (or the owner) sign.
     *
     * @dev Binds the chainless nonce, callData and EntryPoint under the chainless EIP-712 domain
     *      (no chainId). Deliberately excludes the EntryPoint nonce, gas limits and time bounds.
     */
    function getChainlessUserOpHash(uint256 nonce_, bytes calldata callData_) public view returns (bytes32) {
        return _hashChainlessTypedData(
            keccak256(abi.encode(_CHAINLESS_USER_OP_TYPEHASH, nonce_, keccak256(callData_), entryPoint()))
        );
    }

    /**
     * @notice Returns the implementation of the ERC1967 proxy.
     *
     * @return implementation The address of implementation contract.
     */
    function getImplementation() public view returns (address implementation) {
        assembly {
            implementation := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /**
     * @notice Forked from CreateX.
     *
     * @dev Deploys a new contract using the `CREATE` opcode and using the creation
     * bytecode `initCode` and `msg.value` as inputs. In order to save deployment costs,
     * we do not sanity check the `initCode` length. Note that if `msg.value` is non-zero,
     * `initCode` must have a `payable` constructor.
     * @dev Can only be called by this contract.
     * @dev Reverts when new contract is address(0) or code.length is zero.
     *
     * @param initCode_ The creation bytecode.
     * @return newContract The 20-byte address where the contract was deployed.
     */
    function deployCreate(bytes memory initCode_) external payable onlySelf returns (address newContract) {
        assembly ("memory-safe") {
            newContract := create(callvalue(), add(initCode_, 0x20), mload(initCode_))
        }

        if (newContract == address(0) || newContract.code.length == 0) {
            revert FailedContractCreation();
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /// @dev authorizes caller to upgrade the implementation of this contract.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner { }

    /// @dev authorizes caller to update signer set, fallback handlers and modules.
    /// @dev can only be called by this contract.
    function _authorize() internal view override(MultiSignerAuth, FallbackManager, ModuleManager) onlySelf { }

    /**
     * @dev Conditions for a valid owner check:
     *      if owner is non zero, caller must be owner.
     *      If owner is address(0), contract can call itself.
     *      Self-calls inside an owner-signed chainless op count as the owner (this is what lets a
     *      vault owner authorize ownership changes — and upgrades — by signature, replayable on
     *      every chain).
     */
    function _checkOwner() internal view override {
        address owner;
        address caller = msg.sender;

        assembly ("memory-safe") {
            owner := sload(_OWNER_SLOT)
        }

        if (owner == caller) return;
        if (caller == address(this) && (owner == address(0) || uint8(_getChainlessCtx()) == ROLE_OWNER)) return;
        revert Unauthorized();
    }

    /// @dev Reverts unless the live chainless context carries `role_`.
    function _checkChainlessRole(uint8 role_) internal view override {
        if (uint8(_getChainlessCtx()) != role_) revert InvalidChainlessContext();
    }

    /**
     * @dev Validates a chainless userOp: structural constraints, sequential nonce, then signature
     *      over the chainless digest. On success, records the role context consumed by
     *      `executeChainless`.
     */
    function _validateChainlessUserOp(PackedUserOperation calldata userOp_) internal returns (uint256) {
        ChainlessUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (ChainlessUserOpSignature));

        // Zero gas price and no paymaster: replaying a chainless op must never cost the account
        // anything, else old signatures become a gas-griefing vector on every chain.
        if (userOp_.gasFees != bytes32(0) || userOp_.paymasterAndData.length != 0) {
            revert InvalidChainlessUserOp();
        }

        // callData must be executeChainless(nonce, calls) where every call is a zero-value
        // self-call: state sync only, asset movement structurally impossible.
        if (bytes4(userOp_.callData[0:4]) != this.executeChainless.selector) revert InvalidChainlessUserOp();
        (uint256 callDataNonce, Call[] memory calls) = abi.decode(userOp_.callData[4:], (uint256, Call[]));
        if (callDataNonce != signature.nonce) revert InvalidChainlessUserOp();

        uint256 numCalls = calls.length;
        for (uint256 i; i < numCalls; i++) {
            if (calls[i].target != address(this) || calls[i].value != 0) revert InvalidChainlessUserOp();
        }

        uint256 nonce = getChainlessNonce();
        if (signature.nonce != nonce) revert InvalidChainlessNonce(nonce, signature.nonce);
        _setChainlessNonce(nonce + 1);

        bytes32 hash = getChainlessUserOpHash(signature.nonce, userOp_.callData);

        bool isValid = signature.viaOwner
            ? SignatureCheckerLib.isValidSignatureNow(owner(), hash, signature.ownerSignature)
            : _getMultiSignerStorage().isValidSignature(hash, signature.signatures);

        if (!isValid) return UserOperationLib.INVALID_SIGNATURE;

        _setChainlessCtx((signature.nonce << 8) | (signature.viaOwner ? ROLE_OWNER : ROLE_THRESHOLD));

        return UserOperationLib.VALID_SIGNATURE;
    }

    function _getChainlessCtx() internal view returns (uint256 ctx) {
        assembly ("memory-safe") {
            ctx := sload(_CHAINLESS_CTX_SLOT)
        }
    }

    function _setChainlessCtx(uint256 ctx_) internal {
        assembly ("memory-safe") {
            sstore(_CHAINLESS_CTX_SLOT, ctx_)
        }
    }

    function _setChainlessNonce(uint256 nonce_) internal {
        assembly ("memory-safe") {
            sstore(_CHAINLESS_NONCE_SLOT, nonce_)
        }
    }

    /// @dev Get light userOp hash of the Packed user operation.
    function _getLightUserOpHash(
        PackedUserOperation calldata userOp_,
        LightUserOpGasLimits memory gasLimits_
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(userOp_.hashLight(), gasLimits_, entryPoint(), block.chainid));
    }

    /// @dev validates if the given hash (ERC1271) was signed by the signers.
    function _isValidSignature(bytes32 hash_, bytes calldata signature_) internal view override returns (bool) {
        return _getMultiSignerStorage().isValidSignature(hash_, abi.decode(signature_, (ERC1271Signature)).signatures);
    }

    /// @dev validates single userOp signature.
    function _validateSingleUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        SingleUserOpSignature memory signature
    )
        internal
        view
        returns (uint256)
    {
        return _isValidSignature(lightHash_, userOpHash_, signature.signatures);
    }

    /**
     * @dev validates merkelized userOp signature.
     */
    function _validateMerkelizedUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        MerkelizedUserOpSignature memory signature
    )
        internal
        view
        returns (uint256)
    {
        bool isValidMerkleProof = MerkleProof.verify(signature.merkleProof, signature.merkleTreeRoot, userOpHash_);

        if (signature.signatures.length > 1) {
            isValidMerkleProof = isValidMerkleProof
                && MerkleProof.verify(signature.lightMerkleProof, signature.lightMerkleTreeRoot, lightHash_);
        }

        uint256 isValidSig =
            _isValidSignature(signature.lightMerkleTreeRoot, signature.merkleTreeRoot, signature.signatures);

        return isValidMerkleProof ? isValidSig : UserOperationLib.INVALID_SIGNATURE;
    }

    function _isValidSignature(
        bytes32 lightHash_,
        bytes32 hash_,
        MultiSignerLib.SignatureWrapper[] memory signatures
    )
        internal
        view
        returns (uint256 validationData)
    {
        return _getMultiSignerStorage().isValidSignature(lightHash_, hash_, signatures)
            ? UserOperationLib.VALID_SIGNATURE
            : UserOperationLib.INVALID_SIGNATURE;
    }

    function _getSignatureType(bytes1 signatureType_) internal pure returns (SignatureTypes) {
        return SignatureTypes(uint8(signatureType_));
    }

    function _verifyGasLimits(
        PackedUserOperation calldata userOp_,
        LightUserOpGasLimits memory gasLimits_
    )
        internal
        pure
    {
        (uint256 userOpMaxPriorityFeePerGas,) = UserOperationLib.unpackUints(userOp_.gasFees);
        (uint256 verificationGasLimit, uint256 callGasLimit) = UserOperationLib.unpackUints(userOp_.accountGasLimits);

        if (
            userOpMaxPriorityFeePerGas > gasLimits_.maxPriorityFeePerGas || callGasLimit > gasLimits_.callGasLimit
                || userOp_.preVerificationGas > gasLimits_.preVerificationGas
                || verificationGasLimit > gasLimits_.verificationGasLimit
        ) revert InvalidGasLimits();

        if (userOp_.paymasterAndData.length > 0) {
            (address paymaster, uint256 paymasterVerificationGasLimit, uint256 paymasterPostOpGasLimit) =
                UserOperationLib.unpackPaymasterStaticFields(userOp_.paymasterAndData);

            if (
                gasLimits_.paymaster != paymaster
                    || paymasterVerificationGasLimit > gasLimits_.paymasterVerificationGasLimit
                    || paymasterPostOpGasLimit > gasLimits_.paymasterPostOpGasLimit
            ) {
                revert InvalidPaymasterData();
            }
        }
    }
}
