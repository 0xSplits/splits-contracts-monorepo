// SPDX-License-Identifier: GPL-3.0-or-later
// license?
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
 * @notice ERC6909 compliant token warehouse for Splits ecosystem
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

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

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
    string private constant METADATA_PREFIX_NAME = "Splits Wrapped ";

    /// @notice prefix for metadata symbol.
    string private constant METADATA_PREFIX_SYMBOL = "splits";

    /// @notice address of the native token, inline with ERC 7528.
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice NATIVE_TOKEN.toUint256()
    uint256 public constant NATIVE_TOKEN_ID = 1_364_068_194_842_176_056_990_105_843_868_530_818_345_537_040_110;

    /// @notice metadata name of the native token.
    ShortString private immutable NATIVE_TOKEN_NAME;

    /// @notice metadata symbol of the native token.
    ShortString private immutable NATIVE_TOKEN_SYMBOL;

    /// @notice Scale for any numbers representing percentages.
    /// @dev Used for the token withdrawing incentive.
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
        NATIVE_TOKEN_NAME = _native_token_name.toShortString();
        NATIVE_TOKEN_SYMBOL = _native_token_symbol.toShortString();
    }

    /* -------------------------------------------------------------------------- */
    /*                               ERC6909METADATA                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Name of a given token.
     * @param id The id of the token.
     * @return The name of the token.
     */
    function name(uint256 id) external view returns (string memory) {
        if (id == NATIVE_TOKEN_ID) {
            return NATIVE_TOKEN_NAME.toString();
        }
        return string.concat(METADATA_PREFIX_NAME, IERC20(id.toAddress()).name());
    }

    /**
     * @notice Symbol of a given token.
     * @param id The id of the token.
     * @return The symbol of the token.
     */
    function symbol(uint256 id) external view returns (string memory) {
        if (id == NATIVE_TOKEN_ID) {
            return NATIVE_TOKEN_SYMBOL.toString();
        }
        return string.concat(METADATA_PREFIX_SYMBOL, IERC20(id.toAddress()).symbol());
    }

    /**
     * @notice Decimals of a given token.
     * @param id The id of the token.
     * @return The decimals of the token.
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
     * @param _receiver The address that will receive the wrapped tokens.
     * @param _token The address of the token to be deposited.
     * @param _amount The amount of the token to be deposited.
     */
    function deposit(address _receiver, address _token, uint256 _amount) external payable {
        if (_token == NATIVE_TOKEN) {
            if (_amount != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        }

        _mint(_receiver, _token.toUint256(), _amount);
    }

    /**
     * @notice Batch deposits token to the warehouse for the specified addresses from msg.sender.
     * @dev If the token is native, the amount should be sent as value.
     * @param _token The address of the token to be deposited.
     * @param _receivers The addresses that will receive the wrapped tokens.
     * @param _amounts The amounts of the token to be deposited.
     */
    function batchDeposit(
        address[] calldata _receivers,
        address _token,
        uint256[] calldata _amounts
    )
        external
        payable
    {
        if (_receivers.length != _amounts.length) revert LengthMismatch();

        uint256 sum;
        uint256 amount;
        uint256 tokenId = _token.toUint256();
        uint256 length = _receivers.length;
        for (uint256 i; i < length;) {
            amount = _amounts[i];
            sum += amount;
            _mint(_receivers[i], tokenId, amount);

            unchecked {
                ++i;
            }
        }

        if (_token == NATIVE_TOKEN) {
            if (sum != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom(msg.sender, address(this), sum);
        }
    }

    /**
     * @notice Withdraws token from the warehouse for _owner.
     * @dev Bypasses withdrawal incentives.
     * @param _owner The address whose tokens are withdrawn.
     * @param _token The address of the token to be withdrawn.
     */
    function withdraw(address _owner, address _token) external {
        if (msg.sender != _owner && tx.origin != _owner) {
            // nest to reduce gas in the happy-case (solidity/evm won't short circuit)
            if (withdrawConfig[_owner].paused) {
                revert WithdrawalPaused(_owner);
            }
        }

        uint256 amount = balanceOf[_owner][_token.toUint256()] - 1;
        _withdraw({
            _owner: _owner,
            _token: _token,
            _amount: amount,
            _withdrawer: msg.sender,
            _reward: 0
        });
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
        if (_tokens.length != _amounts.length) revert LengthMismatch();
        WithdrawConfig memory config = withdrawConfig[_owner];
        if (config.paused) revert WithdrawalPaused(_owner);

        uint256 reward;
        uint256 length = _tokens.length;
        for (uint256 i; i < length;) {
            reward = _amounts[i] * config.incentive / PERCENTAGE_SCALE;
            _withdraw(_owner, _tokens[i], _amounts[i], _withdrawer, reward);

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Batch transfers tokens to the specified addresses from msg.sender.
     * @param _token The address of the token to be transferred.
     * @param _receivers The addresses of the receivers.
     * @param _amounts The amounts of the tokens to be transferred.
     */
    function batchTransfer(address[] calldata _receivers, address _token, uint256[] calldata _amounts) external {
        if (_receivers.length != _amounts.length) revert LengthMismatch();

        uint256 sum;
        uint256 tokenId = _token.toUint256();
        uint256 amount;
        address receiver;
        uint256 length = _receivers.length;
        for (uint256 i; i < length;) {
            receiver = _receivers[i];
            amount = _amounts[i];

            balanceOf[receiver][tokenId] += amount;
            emit Transfer(msg.sender, msg.sender, receiver, tokenId, amount);
            sum += amount;

            unchecked {
                ++i;
            }
        }
        balanceOf[msg.sender][tokenId] -= sum;
    }

    /**
     * @notice Sets the withdraw config for the msg.sender.
     * @param _config Includes the incentives for withdrawal and their paused state.
     */
    function setWithdrawConfig(WithdrawConfig calldata _config) external {
        withdrawConfig[msg.sender] = _config;
        emit WithdrawConfigUpdated(msg.sender, _config);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    function _withdraw(
        address _owner,
        address _token,
        uint256 _amount,
        address _withdrawer,
        uint256 _reward
    )
        internal
    {
        _burn(_owner, _token.toUint256(), _amount);

        uint256 amountToOwner = _amount - _reward;
        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(amountToOwner);
            if (_reward != 0) payable(_withdrawer).sendValue(_reward);
        } else {
            IERC20(_token).safeTransfer(_owner, amountToOwner);
            if (_reward != 0) IERC20(_token).safeTransfer(_withdrawer, _reward);
        }

        emit Withdraw(_owner, _token, _withdrawer, amountToOwner, _reward);
    }
}
