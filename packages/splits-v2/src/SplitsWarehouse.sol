// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

import { Cast } from "./libraries/Cast.sol";
import { Math } from "./libraries/Math.sol";

import { ERC6909X } from "./tokens/ERC6909X.sol";
import { IERC20Metadata as IERC20 } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { ShortString, ShortStrings } from "@openzeppelin/contracts/utils/ShortStrings.sol";

/**
 * @title Splits Token Warehouse
 * @author Splits
 * @notice ERC6909 compliant token warehouse for splits ecosystem of splitters
 * @dev Token id here is address(uint160(uint256 id)).
 */
contract SplitsWarehouse is ERC6909X {
    using Cast for uint256;
    using Cast for address;
    using Math for uint256[];
    using SafeERC20 for IERC20;
    using Address for address payable;
    using ShortStrings for string;
    using ShortStrings for ShortString;

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
    event WithdrawConfigUpdated(address indexed owner, WithdrawConfig config);
    event Withdraw(
        address indexed owner, address indexed token, address indexed withdrawer, uint256 amount, uint256 reward
    );

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    struct WithdrawConfig {
        uint16 incentive;
        bool paused;
    }

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
    ShortString private immutable nativeTokenName;

    /// @notice metadata symbol of the native token.
    ShortString private immutable nativeTokenSymbol;

    /// @notice Maximum incentive for withdrawing a token.
    uint256 public constant MAX_INCENTIVE = 1e5;

    /// @notice Scale for the incentive for withdrawing a token.
    uint256 public constant PERCENTAGE_SCALE = 1e6;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Withdraw config of a user.
    mapping(address owner => WithdrawConfig config) public withdrawConfig;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(
        string memory _native_token_name,
        string memory _native_token_symbol
    )
        ERC6909X("SplitsWarehouse", "v1")
    {
        nativeTokenName = _native_token_name.toShortString();
        nativeTokenSymbol = _native_token_symbol.toShortString();
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
            return nativeTokenName.toString();
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
            return nativeTokenSymbol.toString();
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
    /*                                  DEPOSIT                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Deposits token to the warehouse for a specified address.
     * @dev If the token is native, the amount should be sent as value.
     * @param _owner The address that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amount The amount of the token to be deposited.
     */
    function deposit(address _owner, address _token, uint256 _amount) external payable {
        if (_owner == address(0)) revert ZeroOwner();
        if (_token == NATIVE_TOKEN) {
            if (_amount != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        }

        _mint(_owner, _token.toUint256(), _amount);
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
        _withdraw(msg.sender, _token.toUint256(), _token, _amount, msg.sender);
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
            _withdraw(msg.sender, _tokens[i].toUint256(), _tokens[i], _amounts[i], msg.sender);

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
     * @param _withdrawer The address that will receive the withdrawer incentive.
     */
    function withdraw(address _owner, address _token, uint256 _amount, address _withdrawer) external {
        WithdrawConfig memory config = withdrawConfig[_owner];
        if (config.paused) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        uint256 reward = _amount * config.incentive / PERCENTAGE_SCALE;

        if (reward > 0) _withdraw(_owner, _token.toUint256(), _token, _amount, reward, _withdrawer);
        else _withdraw(_owner, _token.toUint256(), _token, _amount, _withdrawer);
    }

    /**
     * @notice Withdraws tokens from the warehouse for a specified address.
     * @dev It is recommended to withdraw balance - 1 to save gas.
     * @param _owner The address whose tokens are withdrawn.
     * @param _tokens The addresses of the tokens to be withdrawn.
     * @param _amounts The amounts of the tokens to be withdrawn.
     * @param _withdrawer The address that will receive the withdrawer incentive.
     */
    function withdraw(
        address _owner,
        address[] calldata _tokens,
        uint256[] calldata _amounts,
        address _withdrawer
    )
        external
    {
        WithdrawConfig memory config = withdrawConfig[_owner];
        if (_tokens.length != _amounts.length) revert LengthMismatch();
        if (config.paused) revert WithdrawalPaused(_owner);
        if (_owner == address(0)) revert ZeroOwner();

        if (config.incentive > 0) {
            uint256 reward;
            for (uint256 i; i < _tokens.length;) {
                reward = _amounts[i] * config.incentive / PERCENTAGE_SCALE;
                _withdraw(_owner, _tokens[i].toUint256(), _tokens[i], _amounts[i], reward, _withdrawer);

                unchecked {
                    ++i;
                }
            }
        } else {
            for (uint256 i; i < _tokens.length;) {
                _withdraw(_owner, _tokens[i].toUint256(), _tokens[i], _amounts[i], _withdrawer);

                unchecked {
                    ++i;
                }
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                               BATCH_TRANSFER                               */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice batch transfers tokens to the specified addresses from msg.sender.
     * @param _token The address of the token to be transferred.
     * @param _receivers The addresses of the receivers.
     * @param _amounts The amounts of the tokens to be transferred.
     */
    function batchTransfer(address _token, address[] calldata _receivers, uint256[] calldata _amounts) external {
        uint256 tokenId = _token.toUint256();
        for (uint256 i; i < _receivers.length;) {
            transfer(_receivers[i], tokenId, _amounts[i]);

            unchecked {
                ++i;
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                OWNER ACTIONS                               */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Sets the withdraw config for the msg.sender.
     * @param _config Includes the incentives for withdrawal and their paused state.
     */
    function setWithdrawConfig(WithdrawConfig calldata _config) external {
        withdrawConfig[msg.sender] = _config;
        emit WithdrawConfigUpdated(msg.sender, _config);
    }

    /* -------------------------------------------------------------------------- */
    /*                                    VIEW                                    */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Returns the withdraw config for a specified address.
     * @param _owner The address whose withdraw config is returned.
     * @return config The withdraw config for the specified address.
     */
    function getWithdrawConfig(address _owner) external view returns (WithdrawConfig memory) {
        return withdrawConfig[_owner];
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    function _withdraw(address _owner, uint256 _id, address _token, uint256 _amount, address _withdrawer) internal {
        _burn(_owner, _id, _amount);

        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(_amount);
        } else {
            IERC20(_token).safeTransfer(_owner, _amount);
        }

        emit Withdraw(_owner, _token, _withdrawer, _amount, 0);
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

        uint256 amount = _amount - _reward;

        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(amount);
            payable(_withdrawer).sendValue(_reward);
        } else {
            IERC20(_token).safeTransfer(_owner, amount);
            IERC20(_token).safeTransfer(_withdrawer, _reward);
        }

        emit Withdraw(_owner, _token, _withdrawer, amount, _reward);
    }
}
