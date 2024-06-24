// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import { BaseAccount, IEntryPoint, PackedUserOperation } from "@account-abstraction/core/BaseAccount.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "@account-abstraction/core/Helpers.sol";
import { TokenCallbackHandler } from "@account-abstraction/samples/callback/TokenCallbackHandler.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @dev Forked from
 * https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccount.sol
 */
contract SmartVault is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Primary owner of the smart vault.
    address public root;

    /// @notice Entry point supported by the smart account.
    IEntryPoint private immutable ENTRY_POINT;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error OnlyRoot();
    error OnlyRootOrEntryPoint();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SmartVaultInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyRoot() {
        if (root != msg.sender) revert OnlyRoot();
        _;
    }

    modifier onlyRootOrEntryPoint() {
        if (msg.sender != address(entryPoint()) && msg.sender != root) revert OnlyRootOrEntryPoint();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(address _entryPoint) {
        ENTRY_POINT = IEntryPoint(_entryPoint);
        _disableInitializers();
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    // solhint-disable-next-line no-empty-blocks
    receive() external payable { }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SmartVault must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     * @param _owner the owner (signer) of this account
     */
    function initialize(address _owner) public virtual initializer {
        _initialize(_owner);
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     * @param target target address to call
     * @param value the value to pass in this call
     * @param data the calldata to pass in this call
     */
    function execute(address target, uint256 value, bytes calldata data) external onlyRootOrEntryPoint {
        _call(target, value, data);
    }

    /**
     * execute a sequence of transactions
     * @param calls an array of calls to execute from this account
     */
    function executeBatch(Call[] calldata calls) external onlyRootOrEntryPoint {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{ value: msg.value }(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyRoot {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /// implement template method of BaseAccount
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        if (root != ECDSA.recover(hash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal view override onlyRoot {
        (newImplementation);
    }

    function _initialize(address _root) internal virtual {
        root = _root;
        emit SmartVaultInitialized(ENTRY_POINT, _root);
    }
}
