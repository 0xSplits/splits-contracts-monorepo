// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { MultiSignerSignatureLib } from "../library/MultiSignerSignatureLib.sol";
import { UserOperationLib } from "../library/UserOperationLib.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { FallbackManager } from "../utils/FallbackManager.sol";
import { LightSyncMultiSigner } from "../utils/LightSyncMultiSigner.sol";
import { MultiSigner } from "../utils/MultiSigner.sol";

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { IAccount } from "account-abstraction/interfaces/IAccount.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Ownable } from "solady/auth/Ownable.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/**
 * @title Splits Smart Accounts/Vaults
 *
 * @notice Based on Coinbase's Smart Wallet (https://github.com/coinbase/smart-wallet) and Solady's Smart Wallet.
 * @author Splits
 */
contract SmartVault is IAccount, Ownable, UUPSUpgradeable, LightSyncMultiSigner, ERC1271, FallbackManager {
    using UserOperationLib for PackedUserOperation;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /// @notice Primary Signature types
    enum SignatureTypes {
        SingleUserOp,
        MerkelizedUserOp,
        LightSyncSingleUserOpSignature,
        LightSyncMerkelizedUserOpSignature,
        ERC1271,
        LightSyncERC1271
    }

    /// @notice Single User Op Signature Scheme.
    struct SingleUserOpSignature {
        MultiSignerSignatureLib.SignatureWrapper[] signatures;
    }

    /// @notice Merkelized User Op Signature Scheme.
    struct MerkelizedUserOpSignature {
        /// @notice merkleRoot of all the light(userOp) in the Merkle Tree. If threshold is 1, this will be
        /// bytes32(0).
        bytes32 lightMerkleTreeRoot;
        /// @notice Proof to verify if the light userOp hash is present in the light merkle tree root. If
        /// threshold is 1, this will be empty.
        bytes32[] lightMerkleProof;
        /// @notice merkleRoot of all the user ops in the Merkle Tree.
        bytes32 merkleTreeRoot;
        /// @notice Proof to verify if the userOp hash is present in the root.
        bytes32[] merkleProof;
        /// @notice abi.encode(MultiSignerSignatureLib.SignatureWrapper[]), where threshold - 1
        /// signatures will be verified against the `lightMerkleTreeRoot` and the final signature will be verified
        /// against the `merkleTreeRoot`.
        MultiSignerSignatureLib.SignatureWrapper[] signatures;
    }

    /// @notice Single User Op with Light Sync Updates signature scheme.
    struct LightSyncSingleUserOpSignature {
        LightSyncSignature[] lightSyncSignatures;
        SingleUserOpSignature singleUserOpSignature;
    }

    /// @notice Merkelized User Op with Light Sync Updates signature scheme.
    struct LightSyncMerkelizedUserOpSignature {
        LightSyncSignature[] lightSyncSignatures;
        MerkelizedUserOpSignature merkelizedSignature;
    }

    /// @notice ERC1271 Signature scheme
    struct ERC1271Signature {
        MultiSignerSignatureLib.SignatureWrapper[] signatures;
    }

    /// @notice ERC1271 with Light Sync Updates signature scheme.
    struct LightSyncERC1271Signature {
        LightSyncSignature[] lightSyncSignatures;
        ERC1271Signature erc1271Signature;
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

    /// @notice Thrown when User Operation signature is of unknown type.
    error InvalidUserOpSignatureType();

    /// @notice Thrown when Signature is of unknown type.
    error InvalidSignatureType();

    /// @notice Thrown when merkle root validation fails.
    error InvalidMerkleProof();

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

    constructor(address factory_) ERC1271("splitsSmartVault", "1") {
        FACTORY = factory_;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initializes the account with the `signers` and `threshold`.
     *
     * @dev Reverts if caller is not factory.
     * @dev Reverts if signers or threshold is invalid.
     *
     * @param owner_ Root owner of the smart account.
     * @param signers_ Array of initial signers for this account. Each item should be
     *               an ABI encoded Ethereum address, i.e. 32 bytes with 12 leading 0 bytes,
     *               or a 64 byte public key.
     * @param threshold_ Number of signers required to approve a signature.
     */
    function initialize(address owner_, bytes[] calldata signers_, uint8 threshold_) external payable {
        if (msg.sender != FACTORY) revert OnlyFactory();

        _initializeSigners(signers_, threshold_);
        _initializeOwner(owner_);
    }

    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
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
        bytes32 lightHash = _getLightUserOpHash(userOp_);

        if (signatureType == SignatureTypes.SingleUserOp) {
            SingleUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (SingleUserOpSignature));
            return _validateSingleUserOp(lightHash, userOpHash_, signature);
        } else if (signatureType == SignatureTypes.MerkelizedUserOp) {
            MerkelizedUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (MerkelizedUserOpSignature));
            return _validateMerkelizedUserOp(lightHash, userOpHash_, signature);
        } else if (signatureType == SignatureTypes.LightSyncSingleUserOpSignature) {
            LightSyncSingleUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (LightSyncSingleUserOpSignature));
            return _validateLightSyncSingleUserOpSignature(lightHash, userOpHash_, signature);
        } else if (signatureType == SignatureTypes.LightSyncMerkelizedUserOpSignature) {
            LightSyncMerkelizedUserOpSignature memory signature = abi.decode(userOp_.signature[1:], (LightSyncMerkelizedUserOpSignature));
            return _validateLightSyncMerkelizedUserOp(lightHash, userOpHash_, signature);
        } else {
            revert InvalidSignatureType();
        }
    }

    /**
     * @notice Executes the given call from this account.
     *
     * @dev Can only be called by the Entrypoint or a root owner of this account.
     *
     * @param target_ The address to call.
     * @param value_  The value to send with the call.
     * @param data_   The data of the call.
     */
    function execute(address target_, uint256 value_, bytes calldata data_) external payable onlyEntryPointOrOwner {
        _call(target_, value_, data_);
    }

    /**
     * @notice Executes batch of `Call`s.
     *
     * @dev Can only be called by the Entrypoint or a root owner of this account.
     *
     * @param calls_ The list of `Call`s to execute.
     */
    function executeBatch(Call[] calldata calls_) external payable onlyEntryPointOrOwner {
        uint256 numCalls = calls_.length;
        for (uint256 i; i < numCalls; i++) {
            _call(calls_[i].target, calls_[i].value, calls_[i].data);
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
     *
     * @param initCode_ The creation bytecode.
     * @return newContract The 20-byte address where the contract was deployed.
     */
    function deployCreate(bytes memory initCode_) public payable onlySelf returns (address newContract) {
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

    function _authorize() internal view override(MultiSigner, FallbackManager) onlySelf { }

    /// @dev Get light user op hash of the Packed user operation.
    function _getLightUserOpHash(PackedUserOperation calldata userOp_) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp_.hashLight(), entryPoint(), block.chainid));
    }

    function _call(address target_, uint256 value_, bytes memory data_) internal {
        (bool success, bytes memory result) = target_.call{ value: value_ }(data_);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @dev validates if the given hash (ERC1271) was signed by the signers.
    function _isValidSignature(bytes32 hash_, bytes calldata signature_) internal view override returns (bool) {
        SignatureTypes signatureType = _getSignatureType(signature_[0]);

        if (signatureType == SignatureTypes.ERC1271) {
            return MultiSignerSignatureLib.isValidSignature(
                _getMultiSignerStorage(), hash_, abi.decode(signature_[1:], (ERC1271Signature)).signatures
            );
        } else if (signatureType == SignatureTypes.LightSyncERC1271) {
            LightSyncERC1271Signature memory signature = abi.decode(signature_[1:], (LightSyncERC1271Signature));
            bytes memory addedSigners = _validateAndProcessLightSyncSignaturesMemory(signature.lightSyncSignatures);
            return MultiSignerSignatureLib.isValidSignature(
                _getMultiSignerStorage(), hash_, signature.erc1271Signature.signatures, addedSigners
            );
        } else {
            revert InvalidSignatureType();
        }
    }

    function _validateSingleUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        SingleUserOpSignature memory signature
    )
        internal
        view
        returns (uint256)
    {
        return _isValidSignature(
            lightHash_,
            userOpHash_,
            signature.signatures
        );
    }

    function _validateLightSyncSingleUserOpSignature(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        LightSyncSingleUserOpSignature memory signature
    )
        internal
        returns (uint256)
    {
        _validateAndProcessLightSyncSignatures(signature.lightSyncSignatures);

        return _isValidSignature(lightHash_, userOpHash_, signature.singleUserOpSignature.signatures);
    }

    function _validateMerkelizedUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        MerkelizedUserOpSignature  memory signature
    )
        internal
        view
        returns (uint256 validationData)
    {
        if (!MerkleProof.verify(signature.merkleProof, signature.merkleTreeRoot, userOpHash_)) {
            revert InvalidMerkleProof();
        }

        if (signature.lightMerkleTreeRoot != bytes32(0)) {
            if (
                !MerkleProof.verify(
                    signature.lightMerkleProof, signature.lightMerkleTreeRoot, lightHash_
                )
            ) {
                revert InvalidMerkleProof();
            }
        }

        return _isValidSignature(signature.lightMerkleTreeRoot, signature.merkleTreeRoot, signature.signatures);
    }

    function _validateLightSyncMerkelizedUserOp(
        bytes32 lightHash_,
        bytes32 userOpHash_,
        LightSyncMerkelizedUserOpSignature memory signature
    )
        internal
        returns (uint256 validationData)
    {
        _validateAndProcessLightSyncSignatures(signature.lightSyncSignatures);
        return _validateMerkelizedUserOp(lightHash_, userOpHash_, signature.merkelizedSignature);
    }

    function _isValidSignature(
        bytes32 lightHash_,
        bytes32 hash_,
        MultiSignerSignatureLib.SignatureWrapper[] memory signatures
    )
        internal
        view
        returns (uint256 validationData)
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        uint8 threshold = $.threshold;

        bool isValid = true;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;

        for (uint256 i; i < threshold - 1; i++) {
            signerIndex = signatures[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                MultiSignerLib.isValidSignature(lightHash_, $.signers[signerIndex], signatures[i].signatureData)
                    && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }

        signerIndex = signatures[threshold - 1].signerIndex;
        mask = (1 << signerIndex);

        return (
            MultiSignerLib.isValidSignature(hash_, $.signers[signerIndex], signatures[threshold - 1].signatureData)
                && (alreadySigned & mask == 0) && isValid
        ) ? UserOperationLib.VALID_SIGNATURE : UserOperationLib.INVALID_SIGNATURE;
    }

    function _getSignatureType(bytes1 signatureType_) internal pure returns (SignatureTypes) {
        return SignatureTypes(uint8(signatureType_));
    }
}
