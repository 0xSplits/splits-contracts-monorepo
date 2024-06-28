// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IAccount } from "../interfaces/IAccount.sol";
import { UserOperationLib } from "../library/UserOperationLib.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { MultiSigner } from "../utils/MultiSigner.sol";
import { RootOwner } from "../utils/RootOwner.sol";

import { WebAuthn } from "@web-authn/WebAuthn.sol";
import { Receiver } from "solady/accounts/Receiver.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { UUPSUpgradeable } from "solady/utils/UUPSUpgradeable.sol";

/**
 * @title Splits Smart Wallet
 *
 * @notice Based on Coinbase's Smart Wallet (https://github.com/coinbase/smart-wallet)
 * @author Splits
 */
contract SmartVault is MultiSigner, RootOwner, ERC1271, UUPSUpgradeable, Receiver {
    using UserOperationLib for IAccount.PackedUserOperation;
    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice A wrapper struct used for signature validation so that callers
     *         can identify the owner that signed.
     */
    struct SignatureWrapper {
        /// @dev The index of the signer that signed, see `MultiSigner.signerAtIndex`
        uint8 signerIndex;
        /**
         * @dev If `MultiOwnable.signerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
         *      If `MultiOwnable.signerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
         */
        bytes signatureData;
    }

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

    /// @notice Thrown when number of signatures is less than threshold.
    error MissingSignatures(uint256 signaturesSupplied, uint8 threshold);

    /// @notice Thrown when duplicate signer is encountered.
    error DuplicateSigner(uint8 signerIndex);

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
     * @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
     *                            MAY be zero, in case there is enough deposit, or the userOp has a
     *                            paymaster.
     */
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
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
     * @notice Initializes the account with the `owners`.
     *
     * @dev Reverts if caller is not factory.
     *
     * @param _root Root owner of the smart account.
     * @param _signers Array of initial owners for this account. Each item should be
     *               an ABI encoded Ethereum address, i.e. 32 bytes with 12 leading 0 bytes,
     *               or a 64 byte public key.
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
     * @param userOp              - The operation that is about to be executed.
     * @param userOpHash          - Hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds - Missing funds on the account's deposit in the entrypoint.
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
        IAccount.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        SignatureWrapper[] memory sigWrappers = abi.decode(userOp.signature, (SignatureWrapper[]));
        uint256 numberOfSignatures = sigWrappers.length;

        uint8 threshold_ = threshold();
        if (numberOfSignatures < threshold_) revert MissingSignatures(numberOfSignatures, threshold_);

        if (numberOfSignatures == 1) {
            return _isValidSignature(userOpHash, sigWrappers[0].signerIndex, sigWrappers[0].signatureData) ? 0 : 1;
        }

        bytes32 lightUserOpHash = getLightUserOpHash(userOp);

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bool isValid;

        for (uint256 i; i < numberOfSignatures - 1; i++) {
            isValid = false;
            signerIndex = sigWrappers[i].signerIndex;

            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            isValid = _isValidSignature(lightUserOpHash, signerIndex, sigWrappers[i].signatureData);

            if (isValid) {
                alreadySigned |= mask;
            } else {
                return 1;
            }
        }

        signerIndex = sigWrappers[numberOfSignatures - 1].signerIndex;

        mask = (1 << signerIndex);
        if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

        isValid = _isValidSignature(userOpHash, signerIndex, sigWrappers[numberOfSignatures - 1].signatureData);

        return isValid ? 0 : 1;
    }

    /**
     * @notice Executes the given call from this account.
     *
     * @dev Can only be called by the Entrypoint or an owner of this account (including itself).
     *
     * @param target The address to call.
     * @param value  The value to send with the call.
     * @param data   The data of the call.
     */
    function execute(address target, uint256 value, bytes calldata data) external payable onlyEntryPointOrRoot {
        _call(target, value, data);
    }

    /**
     * @notice Executes batch of `Call`s.
     *
     * @dev Can only be called by the Entrypoint or an owner of this account (including itself).
     *
     * @param calls The list of `Call`s to execute.
     */
    function executeBatch(Call[] calldata calls) external payable onlyEntryPointOrRoot {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
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
     * @param initCode The creation bytecode.
     * @return newContract The 20-byte address where the contract was deployed.
     */
    function deployCreate(bytes memory initCode) public payable onlyAccount returns (address newContract) {
        assembly ("memory-safe") {
            newContract := create(callvalue(), add(initCode, 0x20), mload(initCode))
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
    function getLightUserOpHash(IAccount.PackedUserOperation calldata userOp) internal view returns (bytes32) {
        return keccak256(abi.encode(userOp.hashLight(), entryPoint(), block.chainid));
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @notice validates if the signature provided by the signer at `signerIndex` is valid for the hash.
     */
    function _isValidSignature(
        bytes32 hash,
        uint8 signerIndex,
        bytes memory signature
    )
        internal
        view
        returns (bool isValid)
    {
        bytes memory signer = signerAtIndex(signerIndex);

        if (signer.length == 32) {
            isValid = _isValidSignatureEOA(hash, signer, signature);
        } else {
            isValid = _isValidSignaturePasskey(hash, signer, signature);
        }
    }

    /**
     * @notice validates if the given hash was signed by the signers of this account.
     * @dev used internally for erc1271 isValidSignature.
     */
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper[] memory sigWrappers = abi.decode(signature, (SignatureWrapper[]));
        uint256 numberOfSignatures = sigWrappers.length;

        uint8 threshold_ = threshold();
        if (numberOfSignatures < threshold_) revert MissingSignatures(numberOfSignatures, threshold_);

        uint256 alreadySigned;
        uint256 mask;
        uint8 signerIndex;
        bool isValid;
        for (uint256 i; i < numberOfSignatures; i++) {
            isValid = false;
            signerIndex = sigWrappers[i].signerIndex;
            mask = (1 << signerIndex);
            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            isValid = _isValidSignature(hash, signerIndex, sigWrappers[i].signatureData);

            if (isValid) {
                alreadySigned |= mask;
            } else {
                return false;
            }
        }
        return true;
    }

    function _isValidSignaturePasskey(
        bytes32 hash,
        bytes memory signer,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        (uint256 x, uint256 y) = abi.decode(signer, (uint256, uint256));

        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));

        return WebAuthn.verify({ challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y });
    }

    function _isValidSignatureEOA(
        bytes32 hash,
        bytes memory signer,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        address owner;
        assembly ("memory-safe") {
            owner := mload(add(signer, 32))
        }

        return SignatureCheckerLib.isValidSignatureNow(owner, hash, signature);
    }

    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyRoot { }

    function authorizeUpdate() internal view override(MultiSigner) {
        if (msg.sender != address(this) && msg.sender != root()) revert OnlyAccount();
    }
}
