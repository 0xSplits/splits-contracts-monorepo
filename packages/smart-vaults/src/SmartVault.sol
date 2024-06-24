// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "@account-abstraction/core/BaseAccount.sol";
import "@account-abstraction/core/Helpers.sol";
import "@account-abstraction/samples/callback/TokenCallbackHandler.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

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
    IEntryPoint private immutable _entryPoint;

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

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    // solhint-disable-next-line no-empty-blocks
    receive() external payable { }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
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

    function _initialize(address _owner) internal virtual {
        root = root;
        emit SmartVaultInitialized(_entryPoint, _owner);
    }
}
