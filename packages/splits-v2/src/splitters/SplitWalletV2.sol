// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { ISplitsWarehouse } from "../interfaces/ISplitsWarehouse.sol";

import { Cast } from "../libraries/Cast.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { Wallet } from "../utils/Wallet.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title SplitWalletV2
 * @author Splits
 * @notice The implementation logic for v2 splitters.
 * @dev `SplitProxy` handles `receive()` itself to avoid the gas cost with `DELEGATECALL`.
 */
contract SplitWalletV2 is Wallet {
    using SplitV2Lib for SplitV2Lib.Split;
    using SafeTransferLib for address;
    using SafeERC20 for IERC20;
    using Cast for address;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error UnauthorizedInitializer();
    error InvalidSplit();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitUpdated(SplitV2Lib.Split _split);
    event SplitDistributed(
        address indexed _token,
        address indexed _distributor,
        uint256 _amountDistributed,
        uint256 _distributorReward,
        bool _distributeByPush
    );

    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    /// @notice address of Splits Warehouse
    ISplitsWarehouse public immutable SPLITS_WAREHOUSE;

    /// @notice address of Split Wallet V2 factory
    address public immutable FACTORY;

    /// @notice address of native token
    address public immutable NATIVE_TOKEN;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice the split hash - Keccak256 hash of the split struct
    bytes32 public splitHash;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse) {
        SPLITS_WAREHOUSE = ISplitsWarehouse(_splitWarehouse);
        NATIVE_TOKEN = SPLITS_WAREHOUSE.NATIVE_TOKEN();
        FACTORY = msg.sender;
    }

    /**
     * @notice Initializes the split wallet with a split and its corresponding data.
     * @dev Only the factory can call this function.
     * @param split The split struct containing the split data that gets initialized
     */
    function initialize(SplitV2Lib.Split calldata split, address _owner) external {
        if (msg.sender != FACTORY) revert UnauthorizedInitializer();

        // throws error if invalid
        split.validate();
        splitHash = split.getHash();

        Wallet.__initWallet(_owner);
    }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Distributes the tokens in the split & Warehouse to the recipients.
     * @dev The split must be initialized and the hash of _split must match splitHash.
     * @param _split The split struct containing the split data that gets distributed.
     * @param _token The token to distribute.
     * @param _distributor The distributor of the split.
     */
    function distribute(SplitV2Lib.Split calldata _split, address _token, address _distributor) external pausable {
        if (splitHash != _split.getHash()) revert InvalidSplit();

        (uint256 splitBalance, uint256 warehouseBalance) = getSplitBalance(_token);
        if (_split.distributeByPush) {
            if (warehouseBalance > 1) {
                withdrawFromWarehouse(_token);
                unchecked {
                    warehouseBalance -= 1;
                }
            } else if (warehouseBalance > 0) {
                unchecked {
                    warehouseBalance -= 1;
                }
            }
            pushDistribute(_split, _token, warehouseBalance + splitBalance, _distributor);
        } else {
            if (splitBalance > 1) {
                unchecked {
                    splitBalance -= 1;
                }
                depositToWarehouse(_token, splitBalance);
            } else if (splitBalance > 0) {
                unchecked {
                    splitBalance -= 1;
                }
            }
            pullDistribute(_split, _token, warehouseBalance + splitBalance, _distributor);
        }
    }

    /**
     * @notice Distributes a specific amount of tokens in the split & Warehouse to the recipients.
     * @dev The split must be initialized and the hash of _split must match splitHash.
     * @dev Will revert if the amount of tokens to transfer or distribute doesn't exist.
     * @param _split The split struct containing the split data that gets distributed.
     * @param _token The token to distribute.
     * @param _distributeAmount The amount of tokens to distribute.
     * @param _warehouseTransferAmount The amount of tokens to transfer from/to the warehouse.
     * @param _distributor The distributor of the split.
     */
    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _distributeAmount,
        uint256 _warehouseTransferAmount,
        address _distributor
    )
        external
        pausable
    {
        if (splitHash != _split.getHash()) revert InvalidSplit();

        if (_split.distributeByPush) {
            if (_warehouseTransferAmount != 0) withdrawFromWarehouse(_token);
            pushDistribute(_split, _token, _distributeAmount, _distributor);
        } else {
            if (_warehouseTransferAmount != 0) depositToWarehouse(_token, _warehouseTransferAmount);
            pullDistribute(_split, _token, _distributeAmount, _distributor);
        }
    }

    /**
     * @notice Deposits tokens to the warehouse.
     * @param _token The token to deposit.
     * @param _amount The amount of tokens to deposit
     */
    function depositToWarehouse(address _token, uint256 _amount) public {
        if (_token == NATIVE_TOKEN) {
            SPLITS_WAREHOUSE.deposit{ value: _amount }(address(this), _token, _amount);
        } else {
            if (IERC20(_token).allowance(address(this), address(SPLITS_WAREHOUSE)) < _amount) {
                IERC20(_token).approve(address(SPLITS_WAREHOUSE), type(uint256).max);
            }
            SPLITS_WAREHOUSE.deposit(address(this), _token, _amount);
        }
    }

    /**
     * @notice Withdraws tokens from the warehouse to the split wallet.
     * @param _token The token to withdraw.
     */
    function withdrawFromWarehouse(address _token) public {
        SPLITS_WAREHOUSE.withdraw(address(this), _token);
    }

    /**
     * @notice Gets the total token balance of the split wallet and the warehouse.
     * @param _token The token to get the balance of.
     * @return splitBalance The token balance in the split wallet.
     * @return warehouseBalance The token balance in the warehouse of the split wallet.
     */
    function getSplitBalance(address _token) public view returns (uint256 splitBalance, uint256 warehouseBalance) {
        splitBalance = (_token == NATIVE_TOKEN) ? address(this).balance : IERC20(_token).balanceOf(address(this));
        warehouseBalance = SPLITS_WAREHOUSE.balanceOf(address(this), _token.toUint256());
    }

    /**
     * @notice Updates the split.
     * @dev Only the owner can call this function.
     * @param _split The new split struct.
     */
    function updateSplit(SplitV2Lib.Split calldata _split) external onlyOwner {
        // throws error if invalid
        _split.validate();
        splitHash = _split.getHash();
        emit SplitUpdated(_split);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Assumes the amount is already present in the split wallet.
    function pushDistribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        internal
    {
        uint256 numOfRecipients = _split.recipients.length;
        // NOTE: are these fns silly?
        uint256 distributorReward = _split.calculateDistributorReward(_amount);
        uint256 amountToDistribute = _amount - distributorReward;
        uint256 amountDistributed;
        uint256 allocatedAmount;

        if (_token == NATIVE_TOKEN) {
            for (uint256 i; i < numOfRecipients;) {
                // NOTE: are these fns silly?
                allocatedAmount = _split.calculateAllocatedAmount(amountToDistribute, i);
                amountDistributed += allocatedAmount;

                if (!_split.recipients[i].trySafeTransferETH(allocatedAmount, SafeTransferLib.GAS_STIPEND_NO_GRIEF)) {
                    SPLITS_WAREHOUSE.deposit{ value: allocatedAmount }(_split.recipients[i], _token, allocatedAmount);
                }

                unchecked {
                    ++i;
                }
            }

            if (distributorReward > 0) _distributor.safeTransferETH(distributorReward);
        } else {
            for (uint256 i; i < numOfRecipients;) {
                // NOTE: are these fns silly?
                allocatedAmount = _split.calculateAllocatedAmount(amountToDistribute, i);
                amountDistributed += allocatedAmount;

                IERC20(_token).safeTransfer(_split.recipients[i], allocatedAmount);

                unchecked {
                    ++i;
                }
            }

            if (distributorReward > 0) IERC20(_token).safeTransfer(_distributor, distributorReward);
        }

        emit SplitDistributed(_token, _distributor, amountDistributed, distributorReward, true);
    }

    /// @dev Assumes the amount is already deposited to the warehouse.
    function pullDistribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        internal
    {
        (uint256[] memory amounts, uint256 amountDistributed, uint256 distibutorReward) =
            _split.getDistributions(_amount);
        SPLITS_WAREHOUSE.batchTransfer(_split.recipients, _token, amounts);
        if (distibutorReward > 0) SPLITS_WAREHOUSE.transfer(_distributor, _token.toUint256(), distibutorReward);
        emit SplitDistributed(_token, _distributor, amountDistributed, distibutorReward, false);
    }
}
