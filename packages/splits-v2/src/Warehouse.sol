// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import { Cast } from "./libraries/Cast.sol";
import { Math } from "./libraries/Math.sol";
import { ERC6909Permit } from "./tokens/ERC6909Permit.sol";
import { IERC20Metadata as IERC20 } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title Splits token Warehouse
 * @author Splits
 * @notice ERC6909 compliant token warehouse for splits ecosystem of splitters
 * @dev Token id here is address(uint160(uint256 id)).
 */
contract Warehouse is ERC6909Permit, ReentrancyGuard {
    using Cast for uint256;
    using Cast for address;
    using Math for uint256[];
    using SafeERC20 for IERC20;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidAmount();
    error TokenNotSupported();
    error InvalidDepositParams();
    error ZeroOwner();

    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    /// @notice prefix for metadata name.
    string private constant METADATA_PREFIX_SYMBOL = "Splits";

    /// @notice prefix for metadata symbol.
    string private constant METADATA_PREFIX_NAME = "Splits Wrapped ";

    /// @notice address of the native token.
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice NATIVE_TOKEN.toUint256()
    uint256 public constant NATIVE_TOKEN_ID = 1_364_068_194_842_176_056_990_105_843_868_530_818_345_537_040_110;

    /// @notice metadata name of the native token.
    string private nativeTokenName;

    /// @notice metadata symbol of the native token.
    string private nativeTokenSymbol;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Total supply of a token
    mapping(uint256 id => uint256 amount) public totalSupply;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(
        string memory _name,
        string memory _gas_token_name,
        string memory _gas_token_symbol
    )
        ERC6909Permit(_name)
        ReentrancyGuard()
    {
        nativeTokenName = _gas_token_name;
        nativeTokenSymbol = _gas_token_symbol;
    }

    /* -------------------------------------------------------------------------- */
    /*                               ERC6909METADATA                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Name of a given token.
     * @param id The id of the token.
     * @return name The name of the token.
     */
    function name(uint256 id) external view returns (string memory) {
        if (id == NATIVE_TOKEN_ID) {
            return nativeTokenName;
        }
        return string.concat(METADATA_PREFIX_NAME, IERC20(id.toAddress()).name());
    }

    /**
     * @notice Symbol of a given token.
     * @param id The id of the token.
     * @return symbol The symbol of the token.
     */
    function symbol(uint256 id) external view returns (string memory) {
        if (id == NATIVE_TOKEN_ID) {
            return nativeTokenSymbol;
        }
        return string.concat(METADATA_PREFIX_SYMBOL, IERC20(id.toAddress()).name());
    }

    /**
     * @notice Decimals of a given token.
     * @param id The id of the token.
     * @return decimals The decimals of the token.
     */
    function decimals(uint256 id) external view returns (uint8) {
        if (id == NATIVE_TOKEN_ID) {
            return 18;
        }
        return IERC20(id.toAddress()).decimals();
    }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Deposits token to the warehouse for a specified address.
     * @dev If the token is native, the amount should be sent as value.
     * @param _owner The address that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amount The amount of the token to be deposited.
     */
    function deposit(address _owner, address _token, uint256 _amount) external payable {
        if (_token == NATIVE_TOKEN) {
            if (_amount != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        }

        uint256 id = _token.toUint256();

        _deposit(_owner, id, _amount);
    }

    /**
     * @notice Deposits token to the warehouse for a specified list of addresses.
     * @dev If the token is native, the amount should be sent as value.
     * @param _owners The addresses that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amounts The amounts of the token to be deposited.
     */
    function deposit(address[] calldata _owners, address _token, uint256[] calldata _amounts) external payable {
        if (_owners.length != _amounts.length) revert InvalidDepositParams();

        uint256 totalAmount = _amounts.sum();

        if (_token == NATIVE_TOKEN) {
            if (totalAmount != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom(msg.sender, address(this), totalAmount);
        }

        uint256 id = _token.toUint256();

        _depsoit(_owners, id, _amounts, totalAmount);
    }

    /**
     * @notice Deposits token to the warehouse for a specified address after a transfer.
     * @dev Does not support native token. This should be used as part of a transferAndCall flow.
     *     If the function is not called after transfer someone can front run the deposit.
     * @param _owner The address that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amount The amount of the token to be deposited.
     */
    function depositAfterTransfer(address _owner, address _token, uint256 _amount) external {
        if (_token == NATIVE_TOKEN) revert TokenNotSupported();

        uint256 id = _token.toUint256();

        if (_amount > IERC20(_token).balanceOf(address(this)) - totalSupply[id]) revert InvalidAmount();

        _deposit(_owner, id, _amount);
    }

    /**
     * @notice Deposits token to the warehouse for a specified list of addresses after a transfer.
     * @dev Does not support native token. This should be used as part of a transferAndCall flow.
     *     If the function is not called after transfer someone can front run the deposit.
     * @param _owners The addresses that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amounts The amounts of the token to be deposited.
     */
    function depositAfterTransfer(address[] calldata _owners, address _token, uint256[] calldata _amounts) external {
        if (_owners.length != _amounts.length) revert InvalidDepositParams();
        if (_token == NATIVE_TOKEN) revert TokenNotSupported();

        uint256 id = _token.toUint256();

        uint256 totalAmount = _amounts.sum();

        if (totalAmount > IERC20(_token).balanceOf(address(this)) - totalSupply[id]) revert InvalidAmount();

        _depsoit(_owners, id, _amounts, totalAmount);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    function _deposit(address _owner, uint256 _id, uint256 _amount) internal {
        if (_owner == address(0)) revert ZeroOwner();

        totalSupply[_id] += _amount;
        _mint(_owner, _id, _amount);
    }

    function _depsoit(
        address[] calldata _owners,
        uint256 _id,
        uint256[] calldata _amounts,
        uint256 _totalAmount
    )
        internal
    {
        totalSupply[_id] += _totalAmount;
        for (uint256 i; i < _owners.length; i++) {
            if (_owners[i] == address(0)) revert ZeroOwner();
            _mint(_owners[i], _id, _amounts[i]);
        }
    }
}
