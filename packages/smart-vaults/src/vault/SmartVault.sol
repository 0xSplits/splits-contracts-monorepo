// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IAccount } from "../interfaces/IAccount.sol";
import { UserOperationLib } from "../library/UserOperationLib.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { MultiSigner } from "../utils/MultiSigner.sol";
import { RootOwner } from "../utils/RootOwner.sol";

import { Receiver } from "solady/accounts/Receiver.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/**
 * @title Splits Smart Wallet
 *
 * @notice Based on Coinbase's Smart Wallet (https://github.com/coinbase/smart-wallet) and Solady's Smart Wallet.
 * @author Splits
 */
contract SmartVault is MultiSigner, RootOwner, ERC1271, UUPSUpgradeable, Receiver {
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

        initializeSigners(_signers, _threshold);
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
        bytes memory signature = preValidationStateSync(_userOp.signature);

        SignatureWrapper[] memory sigWrappers = abi.decode(signature, (NormalSignature)).signature;
        uint256 numberOfSignatures = sigWrappers.length;

        uint8 threshold_ = getThreshold();
        if (numberOfSignatures < threshold_) revert MissingSignatures(numberOfSignatures, threshold_);

        if (numberOfSignatures == 1) {
            return validateSignature(_userOpHash, sigWrappers[0].signerIndex, sigWrappers[0].signatureData) ? 0 : 1;
        }

        bytes32 lightUserOpHash = getLightUserOpHash(_userOp);

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bool isValid;

        for (uint256 i; i < numberOfSignatures - 1; i++) {
            isValid = false;
            signerIndex = sigWrappers[i].signerIndex;

            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            isValid = validateSignature(lightUserOpHash, signerIndex, sigWrappers[i].signatureData);

            if (isValid) {
                alreadySigned |= mask;
            } else {
                return 1;
            }
        }

        signerIndex = sigWrappers[numberOfSignatures - 1].signerIndex;

        mask = (1 << signerIndex);
        if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

        return validateSignature(_userOpHash, signerIndex, sigWrappers[numberOfSignatures - 1].signatureData) ? 0 : 1;
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
    function implementation() public view returns (address implementation_) {
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
    function getLightUserOpHash(IAccount.PackedUserOperation calldata _userOp) internal view returns (bytes32) {
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

    function authorizeUpdate() internal view override(MultiSigner) {
        if (msg.sender != address(this) && msg.sender != root()) revert OnlyAccount();
    }

    /**
     * @notice validates if the given hash was signed by the signers.
     */
    function _isValidSignature(bytes32 _hash, bytes calldata _signature) internal view override returns (bool) {
        Signature memory signature = abi.decode(_signature, (Signature));

        if (signature.sigType == SignatureType.chained) {
            ChainedSignature memory chainedSignature = abi.decode(signature.signature, (ChainedSignature));
            (bytes[256] memory signers, uint8 threshold) = processsSignerUpdatesMemory(chainedSignature.updates);
            return validateNormalSignature(_hash, chainedSignature.normalSignature, signers, threshold);
        } else if (signature.sigType == SignatureType.normal) {
            return validateNormalSignature(_hash, signature.signature);
        } else {
            revert();
        }
    }

    function preValidationStateSync(bytes memory _signature) internal returns (bytes memory) {
        Signature memory signature = abi.decode(_signature, (Signature));

        if (signature.sigType == SignatureType.chained) {
            ChainedSignature memory chainedSignature = abi.decode(signature.signature, (ChainedSignature));
            processSignerUpdates(chainedSignature.updates);
            return chainedSignature.normalSignature;
        } else if (signature.sigType == SignatureType.normal) {
            return signature.signature;
        } else {
            revert();
        }
    }
}
