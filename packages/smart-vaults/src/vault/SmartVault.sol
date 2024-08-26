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
        ERC1271
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

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Splits smart vaults factory.
    address public immutable FACTORY;

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

    /// @notice Thrown when merkle root validation fails.
    error InvalidMerkleProof();

    /// @notice Thrown when LightUserOpGasLimits have been breached.
    error InvalidGasLimits();

    /// @notice Thrown when Paymaster LightUserOpGasLimits have been breached.
    error InvalidPaymasterData();

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
        } else {
            revert InvalidSignatureType();
        }
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
     */
    function _checkOwner() internal view override {
        address owner;
        address caller = msg.sender;

        assembly ("memory-safe") {
            owner := sload(_OWNER_SLOT)
        }

        if (owner == caller) return;
        if (owner == address(0) && caller == address(this)) return;
        revert Unauthorized();
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
     * @dev Reverts when merkle proof is invalid.
     */
    function _validateMerkelizedUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        MerkelizedUserOpSignature memory signature
    )
        internal
        view
        returns (uint256 validationData)
    {
        if (!MerkleProof.verify(signature.merkleProof, signature.merkleTreeRoot, userOpHash_)) {
            revert InvalidMerkleProof();
        }

        if (signature.signatures.length > 1) {
            if (!MerkleProof.verify(signature.lightMerkleProof, signature.lightMerkleTreeRoot, lightHash_)) {
                revert InvalidMerkleProof();
            }
        }

        return _isValidSignature(signature.lightMerkleTreeRoot, signature.merkleTreeRoot, signature.signatures);
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
