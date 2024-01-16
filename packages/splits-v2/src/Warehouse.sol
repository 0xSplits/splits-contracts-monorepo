// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

import { Cast } from "./libraries/Cast.sol";
import { Math } from "./libraries/Math.sol";

import { ERC6909Permit } from "./tokens/ERC6909Permit.sol";
import { IERC20Metadata as IERC20 } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title Splits token Warehouse
 * @author Splits
 * @notice ERC6909 compliant token warehouse for splits ecosystem of splitters
 * @dev Token id here is address(uint160(uint256 id)).
 */
contract Warehouse is ERC6909Permit {
    using Cast for uint256;
    using Cast for address;
    using Math for uint256[];
    using SafeERC20 for IERC20;
    using Address for address payable;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidAmount();
    error LengthMismatch();
    error ZeroOwner();
    error WithdrawalPaused(address owner);
    error InvalidIncentive();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event WithdrawalsPaused(address indexed owner, bool paused);
    event WithdrawIncentiveSet(address indexed owner, uint256 incentive);

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

    /// @notice Maximum incentive for withdrawing a token.
    uint256 public constant MAX_INCENTIVE = 1e5;

    /// @notice Scale for the incentive for withdrawing a token.
    uint256 public constant INCENTIVE_SCALE = 1e6;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Total supply of a token.
    mapping(uint256 id => uint256 amount) public totalSupply;

    /// @notice Whether a token withdrawal is paused for a given address.
    mapping(address owner => bool isPaused) public isWithdrawPaused;

    /// @notice Incentive for withdrawing a token.
    mapping(address owner => uint256 incentive) public withdrawIncentive;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(
        string memory _name,
        string memory _native_token_name,
        string memory _native_token_symbol
    )
        ERC6909Permit(_name)
    {
        nativeTokenName = _native_token_name;
        nativeTokenSymbol = _native_token_symbol;
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

    /* -------------------------------------------------------------------------- */
    /*                                  DESPOSIT                                  */
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
        if (_owners.length != _amounts.length) revert LengthMismatch();

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
        if (_owners.length != _amounts.length) revert LengthMismatch();

        uint256 id = _token.toUint256();

        uint256 totalAmount = _amounts.sum();

        if (totalAmount > IERC20(_token).balanceOf(address(this)) - totalSupply[id]) revert InvalidAmount();

        _depsoit(_owners, id, _amounts, totalAmount);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  WITHDRAW                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Withdraws token from the warehouse for msg.sender.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _token The address of the token to be withdrawn.
     * @param _amount The amount of the token to be withdrawn.
     */
    function withdraw(address _token, uint256 _amount) external {
        _withdraw(msg.sender, _token.toUint256(), _token, _amount);
    }

    /**
     * @notice Withdraws tokens from the warehouse for msg.sender.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _tokens The addresses of the tokens to be withdrawn.
     * @param _amounts The amounts of the tokens to be withdrawn.
     */
    function withdraw(address[] memory _tokens, uint256[] memory _amounts) external {
        if (_tokens.length != _amounts.length) revert LengthMismatch();

        for (uint256 i; i < _tokens.length;) {
            _withdraw(msg.sender, _tokens[i].toUint256(), _tokens[i], _amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Withdraws token from the warehouse for a specified address.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _owner The address whose tokens are withdrawn.
     * @param _token The address of the token to be withdrawn.
     * @param _amount The amount of the token to be withdrawn.
     */
    function withdraw(address _owner, address _token, uint256 _amount) external {
        if (isWithdrawPaused[_owner]) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        _withdraw(_owner, _token.toUint256(), _token, _amount);
    }

    /**
     * @notice Withdraws tokens from the warehouse for a specified address.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _owner The address whose tokens are withdrawn.
     * @param _tokens The addresses of the tokens to be withdrawn.
     * @param _amounts The amounts of the tokens to be withdrawn.
     */
    function withdraw(address _owner, address[] calldata _tokens, uint256[] calldata _amounts) external {
        if (_tokens.length != _amounts.length) revert LengthMismatch();
        if (isWithdrawPaused[_owner]) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        for (uint256 i; i < _tokens.length;) {
            _withdraw(_owner, _tokens[i].toUint256(), _tokens[i], _amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Withdraws token from the warehouse for a specified address with incentives for the withdrawer.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _owner The address whose tokens are withdrawn.
     * @param _token The address of the token to be withdrawn.
     * @param _amount The amount of the token to be withdrawn.
     * @param _withdrawer The address that will receive the withdrawer incentive.
     */
    function withdrawWithIncentive(address _owner, address _token, uint256 _amount, address _withdrawer) external {
        if (isWithdrawPaused[_owner]) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        uint256 reward = _amount * withdrawIncentive[_owner] / INCENTIVE_SCALE;
        _withdraw(_owner, _token.toUint256(), _token, _amount, reward, _withdrawer);
    }

    /**
     * @notice Withdraws tokens from the warehouse for a specified address with incentives for the withdrawer.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _owner The address whose tokens are withdrawn.
     * @param _tokens The addresses of the tokens to be withdrawn.
     * @param _amounts The amounts of the tokens to be withdrawn.
     * @param _withdrawer The address that will receive the withdrawer incentive.
     */
    function withdrawWithIncentive(
        address _owner,
        address[] calldata _tokens,
        uint256[] calldata _amounts,
        address _withdrawer
    )
        external
    {
        if (_tokens.length != _amounts.length) revert LengthMismatch();
        if (isWithdrawPaused[_owner]) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        uint256 incentive = withdrawIncentive[_owner];
        uint256 reward;

        for (uint256 i; i < _tokens.length;) {
            reward = _amounts[i] * incentive / INCENTIVE_SCALE;
            _withdraw(_owner, _tokens[i].toUint256(), _tokens[i], _amounts[i], reward, _withdrawer);

            unchecked {
                ++i;
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                OWNER ACTIONS                               */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Pauses withdrawals for msg.sender.
     * @param pause Whether to pause or unpause.
     */
    function pauseWithdrawals(bool pause) external {
        isWithdrawPaused[msg.sender] = pause;
        emit WithdrawalsPaused(msg.sender, pause);
    }

    /**
     * @notice Sets the incentive for withdrawing tokens for msg.sender.
     * @param _incentive The incentive for withdrawing tokens.
     */
    function setWithdrawIncentive(uint256 _incentive) external {
        if (_incentive > MAX_INCENTIVE) revert InvalidIncentive();
        withdrawIncentive[msg.sender] = _incentive;
        emit WithdrawIncentiveSet(msg.sender, _incentive);
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
        for (uint256 i; i < _owners.length;) {
            if (_owners[i] == address(0)) revert ZeroOwner();
            _mint(_owners[i], _id, _amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    function _withdraw(address _owner, uint256 _id, address _token, uint256 _amount) internal {
        _burn(_owner, _id, _amount);
        totalSupply[_id] -= _amount;

        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(_amount);
        } else {
            IERC20(_token).safeTransfer(_owner, _amount);
        }
    }

    function _withdraw(
        address _owner,
        uint256 _id,
        address _token,
        uint256 _amount,
        uint256 _reward,
        address _withdrawer
    )
        internal
    {
        _burn(_owner, _id, _amount);
        totalSupply[_id] -= _amount;

        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(_amount - _reward);
            payable(_withdrawer).sendValue(_reward);
        } else {
            IERC20(_token).safeTransfer(_owner, _amount - _reward);
            IERC20(_token).safeTransfer(_withdrawer, _reward);
        }
    }
}
