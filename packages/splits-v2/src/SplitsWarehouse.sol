// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Cast } from "./libraries/Cast.sol";

import { ERC6909X } from "./tokens/ERC6909X.sol";
import { IERC20Metadata as IERC20 } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { ShortString, ShortStrings } from "@openzeppelin/contracts/utils/ShortStrings.sol";

/**
 * @title Splits Token Warehouse
 * @author Splits
 * @notice ERC6909 compliant token warehouse for Splits ecosystem
 * @dev Token id here is uint256(uint160(address tokenAddress)).
 */
contract SplitsWarehouse is ERC6909X {
    using Cast for uint256;
    using Cast for address;
    using SafeERC20 for IERC20;
    using Address for address payable;
    using ShortStrings for string;
    using ShortStrings for ShortString;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidAmount();
    error LengthMismatch();
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

    /**
     * @notice Withdraw config for a user.
     * @param incentive The incentive for withdrawing tokens.
     * @param paused The paused state of the withdrawal.
     */
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

    /// @notice uint256 representation of the native token.
    uint256 public constant NATIVE_TOKEN_ID = uint256(uint160(NATIVE_TOKEN));

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

    /**
     * @notice Constructs the SplitsWarehouse contract.
     * @param _native_token_name The name of the native token.
     * @param _native_token_symbol The symbol of the native token.
     */
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
            IERC20(_token).safeTransferFrom({ from: msg.sender, to: address(this), value: _amount });
        }

        _mint({ _receiver: _receiver, _id: _token.toUint256(), _amount: _amount });
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

        for (uint256 i; i < length; ++i) {
            amount = _amounts[i];
            sum += amount;
            _mint({ _receiver: _receivers[i], _id: tokenId, _amount: amount });
        }

        if (_token == NATIVE_TOKEN) {
            if (sum != msg.value) revert InvalidAmount();
        } else {
            IERC20(_token).safeTransferFrom({ from: msg.sender, to: address(this), value: sum });
        }
    }

    /**
     * @notice Withdraws token from the warehouse for _owner.
     * @dev Bypasses withdrawal incentives.
     * @param _owner The address whose tokens are withdrawn.
     * @param _token The address of the token to be withdrawn.
     */
    function withdraw(address _owner, address _token) external {
        // solhint-disable-next-line avoid-tx-origin
        if (msg.sender != _owner && tx.origin != _owner) {
            if (withdrawConfig[_owner].paused) {
                revert WithdrawalPaused(_owner);
            }
        }

        // leave 1 to save gas.
        uint256 amount = balanceOf[_owner][_token.toUint256()] - 1;

        _withdraw({ _owner: _owner, _token: _token, _amount: amount, _withdrawer: msg.sender, _reward: 0 });
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

        for (uint256 i; i < length; ++i) {
            reward = _amounts[i] * config.incentive / PERCENTAGE_SCALE;

            _withdraw({
                _owner: _owner,
                _token: _tokens[i],
                _amount: _amounts[i],
                _withdrawer: _withdrawer,
                _reward: reward
            });
        }
    }

    /**
     * @notice Batch transfers tokens to the specified addresses from msg.sender.
     * @param _receivers The addresses of the receivers.
     * @param _token The address of the token to be transferred.
     * @param _amounts The amounts of the tokens to be transferred.
     */
    function batchTransfer(address[] calldata _receivers, address _token, uint256[] calldata _amounts) external {
        if (_receivers.length != _amounts.length) revert LengthMismatch();

        uint256 sum;
        uint256 amount;
        address receiver;

        uint256 tokenId = _token.toUint256();
        uint256 length = _receivers.length;

        for (uint256 i; i < length; ++i) {
            receiver = _receivers[i];
            amount = _amounts[i];

            balanceOf[receiver][tokenId] += amount;
            emit Transfer({ caller: msg.sender, sender: msg.sender, receiver: receiver, id: tokenId, amount: amount });

            sum += amount;
        }

        balanceOf[msg.sender][tokenId] -= sum;
    }

    /**
     * @notice Sets the withdraw config for the msg.sender.
     * @param _config Includes the incentives for withdrawal and their paused state.
     */
    function setWithdrawConfig(WithdrawConfig calldata _config) external {
        withdrawConfig[msg.sender] = _config;
        emit WithdrawConfigUpdated({ owner: msg.sender, config: _config });
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
        _burn({ _sender: _owner, _id: _token.toUint256(), _amount: _amount });

        uint256 amountToOwner = _amount - _reward;

        if (_token == NATIVE_TOKEN) {
            payable(_owner).sendValue(amountToOwner);

            if (_reward != 0) payable(_withdrawer).sendValue(_reward);
        } else {
            IERC20(_token).safeTransfer({ to: _owner, value: amountToOwner });

            if (_reward != 0) IERC20(_token).safeTransfer({ to: _withdrawer, value: _reward });
        }

        // solhint-disable-next-line
        emit Withdraw({ owner: _owner, token: _token, withdrawer: _withdrawer, amount: amountToOwner, reward: _reward });
    }
}
