// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IAccount } from "../interfaces/IAccount.sol";

import { MultiSignerLib } from "../library/MultiSignerLib.sol";
import { MultiSignerSignatureLib } from "../library/MultiSignerSignatureLib.sol";
import { UserOperationLib } from "../library/UserOperationLib.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { LightSyncMultiSigner } from "../utils/LightSyncMultiSigner.sol";
import { MultiSigner } from "../utils/MultiSigner.sol";
import { RootOwner } from "../utils/RootOwner.sol";

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { Receiver } from "solady/accounts/Receiver.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/**
 * @title Splits Smart Wallet
 *
 * @notice Based on Coinbase's Smart Wallet (https://github.com/coinbase/smart-wallet) and Solady's Smart Wallet.
 * @author Splits
 */
contract SmartVault is LightSyncMultiSigner, RootOwner, ERC1271, UUPSUpgradeable, Receiver {
    using UserOperationLib for IAccount.PackedUserOperation;
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
    enum SignatureType {
        UserOp,
        LightSync
    }

    /// @notice Primary signature
    struct Signature {
        SignatureType sigType;
        /**
         * @dev Signature can be of the following types:
         *      UserOp: abi.encode(UserOpSignature)
         *      LightSync: abi.encode(LightSyncSignature)
         */
        bytes signature;
    }

    /// @notice User op signature types
    enum UserOpSignatureType {
        Single,
        Multi
    }

    /// @notice User operation signature
    struct UserOpSignature {
        UserOpSignatureType sigType;
        /**
         * @dev Signature can be of the following types:
         *      Single: abi.encode(MultiSignerSignatureLib.Signature)
         *      Multi: abi.encode(MultiOpSignature)
         */
        bytes signature;
    }

    /// @notice Multiple user op signature using merkle tree.
    struct MultiOpSignature {
        /// @notice merkleRoot of all the light(userOp) signers want to execute. If threshold is 1, this will be
        /// bytes32(0).
        bytes32 lightMerkleTreeRoot;
        /// @notice list of proofs to verify if the light userOp hash is present in the light merkle tree root. If
        /// threshold is 1, this will be empty.
        bytes32[] lightMerkleProof;
        /// @notice merkleRoot of all the user ops signers want to execute.
        bytes32 merkleTreeRoot;
        /// @notice list of proofs to verify if the userOp hash is present in the root.
        bytes32[] merkleProof;
        /// @notice abi.encode(MultiSignerSignatureLib.Signature), where threshold - 1
        /// signatures will be verified against the light root and the final signature will be verified against the
        /// root.
        bytes normalSignature;
    }

    /// @notice Light sync signature
    struct LightSyncSignature {
        /// @notice list of signer set updates.
        SignerSetUpdate[] updates;
        /// @notice abi.encode(UserOPSignature)
        bytes userOpSignature;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Smart Vault Factory;
    address public immutable factory;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when `initialize` is called but the account is already initialized.
    error Initialized();

    /// @notice Thrown when caller is not entry point.
    error OnlyEntryPoint();

    /// @notice Thrown when caller is not factory.
    error OnlyFactory();

    /// @notice Thrown when caller is not address(this).
    error OnlyAccount();

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

    /// @notice Reverts if the caller is neither the EntryPoint, the root, nor the account itself when root is zero.
    modifier onlyEntryPointOrRoot() virtual {
        if (msg.sender != entryPoint()) {
            checkRoot();
        }
        _;
    }

    /// @notice Reverts when caller is not this account.
    modifier onlyAccount() virtual {
        if (msg.sender != address(this)) {
            revert OnlyAccount();
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
     * @param _missingAccountFunds The minimum value this modifier should send the EntryPoint which
     *                            MAY be zero, in case there is enough deposit, or the userOp has a
     *                            paymaster.
     */
    modifier payPrefund(uint256 _missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if _missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), _missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(address _factory) ERC1271("splitSmartVault", "1") {
        factory = _factory;
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Initializes the account with the `signers`.
     *
     * @dev Reverts if caller is not factory.
     *
     * @param _root Root owner of the smart account.
     * @param _signers Array of initial signers for this account. Each item should be
     *               an ABI encoded Ethereum address, i.e. 32 bytes with 12 leading 0 bytes,
     *               or a 64 byte public key.
     * @param _threshold Number of signers required to approve a signature.
     */
    function initialize(address _root, bytes[] calldata _signers, uint8 _threshold) external payable {
        if (msg.sender != factory) revert OnlyFactory();

        _initializeSigners(_signers, _threshold);
        initializeRoot(_root);
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
     * @param _userOp              - The operation that is about to be executed.
     * @param _userOpHash          - Hash of the user's request data. can be used as the basis for signature.
     * @param _missingAccountFunds - Missing funds on the account's deposit in the entrypoint.
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
        IAccount.PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256 _missingAccountFunds
    )
        external
        onlyEntryPoint
        payPrefund(_missingAccountFunds)
        returns (uint256 validationData)
    {
        bytes memory signature = _preValidationStateSync(_userOp.signature);

        UserOpSignature memory userOpSignature = abi.decode(signature, (UserOpSignature));

        if (userOpSignature.sigType == UserOpSignatureType.Single) {
            return _validateSingleUserOp(_userOp, _userOpHash, userOpSignature.signature);
        } else if (userOpSignature.sigType == UserOpSignatureType.Multi) {
            return _validateMultiUserOp(_userOp, _userOpHash, userOpSignature.signature);
        }
        revert InvalidUserOpSignatureType();
    }

    /**
     * @notice Executes the given call from this account.
     *
     * @dev Can only be called by the Entrypoint or a root owner of this account.
     *
     * @param _target The address to call.
     * @param _value  The value to send with the call.
     * @param _data   The data of the call.
     */
    function execute(address _target, uint256 _value, bytes calldata _data) external payable onlyEntryPointOrRoot {
        _call(_target, _value, _data);
    }

    /**
     * @notice Executes batch of `Call`s.
     *
     * @dev Can only be called by the Entrypoint or a root owner of this account.
     *
     * @param _calls The list of `Call`s to execute.
     */
    function executeBatch(Call[] calldata _calls) external payable onlyEntryPointOrRoot {
        for (uint256 i; i < _calls.length; i++) {
            _call(_calls[i].target, _calls[i].value, _calls[i].data);
        }
    }

    /// @notice Returns the address of the EntryPoint v0.7.
    function entryPoint() public view virtual returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    /**
     * @notice Returns the implementation of the ERC1967 proxy.
     *
     * @return implementation_ The address of implementation contract.
     */
    function getImplementation() public view returns (address implementation_) {
        assembly {
            implementation_ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /**
     * @notice Forked from CreateX.
     * @dev Deploys a new contract via calling the `CREATE` opcode and using the creation
     * bytecode `initCode` and `msg.value` as inputs. In order to save deployment costs,
     * we do not sanity check the `initCode` length. Note that if `msg.value` is non-zero,
     * `initCode` must have a `payable` constructor.
     * @param _initCode The creation bytecode.
     * @return newContract The 20-byte address where the contract was deployed.
     */
    function deployCreate(bytes memory _initCode) public payable onlyAccount returns (address newContract) {
        assembly ("memory-safe") {
            newContract := create(callvalue(), add(_initCode, 0x20), mload(_initCode))
        }

        if (newContract == address(0) || newContract.code.length == 0) {
            revert FailedContractCreation();
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Get light user op hash for the giver userOp
     */
    function _getLightUserOpHash(IAccount.PackedUserOperation calldata _userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(_userOp.hashLight(), entryPoint(), block.chainid));
    }

    function _call(address _target, uint256 _value, bytes memory _data) internal {
        (bool success, bytes memory result) = _target.call{ value: _value }(_data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyRoot { }

    function _authorizeUpdate() internal view override(MultiSigner) {
        if (msg.sender != address(this) && msg.sender != _getRoot()) revert OnlyAccount();
    }

    /**
     * @notice validates if the given hash was signed by the signers.
     */
    function _isValidSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        Signature memory rootSignature = abi.decode(_signature, (Signature));

        if (rootSignature.sigType == SignatureType.LightSync) {
            LightSyncSignature memory stateSyncSignature = abi.decode(rootSignature.signature, (LightSyncSignature));
            (bytes[256] memory signers, uint8 threshold) = _processSignerSetUpdatesMemory(stateSyncSignature.updates);

            UserOpSignature memory userOpSignature = abi.decode(stateSyncSignature.userOpSignature, (UserOpSignature));
            return MultiSignerSignatureLib.isValidSignature({
                $: _getMultiSignerStorage(),
                _signers: signers,
                _threshold: threshold,
                _hash: _hash,
                _signature: userOpSignature.signature
            });
        } else if (rootSignature.sigType == SignatureType.UserOp) {
            UserOpSignature memory userOpSignature = abi.decode(rootSignature.signature, (UserOpSignature));
            return MultiSignerSignatureLib.isValidSignature(_getMultiSignerStorage(), _hash, userOpSignature.signature);
        } else {
            revert InvalidSignatureType();
        }
    }

    /// @notice decodes signature, updates state and returns the user op signature
    function _preValidationStateSync(bytes memory _signature) internal returns (bytes memory) {
        Signature memory rootSignature = abi.decode(_signature, (Signature));

        if (rootSignature.sigType == SignatureType.LightSync) {
            LightSyncSignature memory stateSyncSignature = abi.decode(rootSignature.signature, (LightSyncSignature));
            _processSignerSetUpdates(stateSyncSignature.updates);
            return stateSyncSignature.userOpSignature;
        } else if (rootSignature.sigType == SignatureType.UserOp) {
            return rootSignature.signature;
        } else {
            revert InvalidSignatureType();
        }
    }

    /// @notice Validates a single user operation. First n-1 signatures are verified against a light user op hash of
    /// `_userOp`. The nth signature is verified against `_userOpHash`.
    function _validateSingleUserOp(
        IAccount.PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        bytes memory _signature
    )
        internal
        view
        returns (uint256 validationData)
    {
        return _validateSignature(_getLightUserOpHash(_userOp), _userOpHash, _signature);
    }

    /// @notice Validates a multi user op signature using merkleProofs.
    function _validateMultiUserOp(
        IAccount.PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        bytes memory _signature
    )
        internal
        view
        returns (uint256 validationData)
    {
        MultiOpSignature memory signature = abi.decode(_signature, (MultiOpSignature));
        bytes32 lightHash = _getLightUserOpHash(_userOp);

        if (signature.lightMerkleTreeRoot != bytes32(0)) {
            if (!MerkleProof.verify(signature.lightMerkleProof, signature.lightMerkleTreeRoot, lightHash)) {
                revert InvalidMerkleProof();
            }
        }
        if (!MerkleProof.verify(signature.merkleProof, signature.merkleTreeRoot, _userOpHash)) {
            revert InvalidMerkleProof();
        }
        return _validateSignature(signature.lightMerkleTreeRoot, signature.merkleTreeRoot, signature.normalSignature);
    }

    function _validateSignature(
        bytes32 _lightHash,
        bytes32 _hash,
        bytes memory _signature
    )
        internal
        view
        returns (uint256 validationData)
    {
        MultiSignerLib.MultiSignerStorage storage $ = _getMultiSignerStorage();
        MultiSignerSignatureLib.SignatureWrapper[] memory sigWrappers =
            abi.decode(_signature, (MultiSignerSignatureLib.Signature)).signature;

        uint8 threshold = $.threshold;

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bool isValid;

        for (uint256 i; i < threshold - 1; i++) {
            isValid = false;
            signerIndex = sigWrappers[i].signerIndex;

            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) return UserOperationLib.INVALID_SIGNATURE;

            isValid = MultiSignerLib.isValidSignature(_lightHash, $.signers[signerIndex], sigWrappers[i].signatureData);

            if (isValid) {
                alreadySigned |= mask;
            } else {
                return UserOperationLib.INVALID_SIGNATURE;
            }
        }

        signerIndex = sigWrappers[threshold - 1].signerIndex;

        mask = (1 << signerIndex);
        if (alreadySigned & mask != 0) return UserOperationLib.INVALID_SIGNATURE;

        return MultiSignerLib.isValidSignature(_hash, $.signers[signerIndex], sigWrappers[threshold - 1].signatureData)
            ? UserOperationLib.VALID_SIGNATURE
            : UserOperationLib.INVALID_SIGNATURE;
    }
}
