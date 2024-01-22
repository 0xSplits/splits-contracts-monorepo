// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { ISplitsWarehouse } from "../interfaces/ISplitsWarehouse.sol";

import { Cast } from "../libraries/Cast.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { Wallet } from "../utils/Wallet.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
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
    using Cast for address;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error UnauthorizedInitializer();
    error InvalidSplit();
    error ZeroAddress();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitUpdated(address indexed _owner, SplitV2Lib.Split _split);
    event DistributeDirectionUpdated(bool _distributeByPush);
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
    address public immutable NATIVE;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Controls the distribution direction of the split
    bool public distributeByPush;

    /// @notice the split hash - Keccak256 hash of the split struct
    bytes32 public splitHash;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse) {
        SPLITS_WAREHOUSE = ISplitsWarehouse(_splitWarehouse);
        NATIVE = SPLITS_WAREHOUSE.NATIVE_TOKEN();
        FACTORY = msg.sender;
    }

    /**
     * @notice Initializes the split wallet with a split and its corresponding data.
     * @dev Only the factory can call this function. By default, the distribution direction is push and distributions
     * are unpaused.
     * @param split the split struct containing the split data that gets initialized
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
     * @notice Distributes the split to the recipients. It distributes the amount of tokens present in Warehouse and the
     * split wallet.
     * @dev The split must be initialized and the split hash must match the split hash of the split wallet.
     * @param _split the split struct containing the split data that gets distributed
     * @param _token the token to distribute
     * @param _distributor the distributor of the split
     */
    function distribute(SplitV2Lib.Split calldata _split, address _token, address _distributor) external pausable {
        if (splitHash != _split.getHash()) revert InvalidSplit();
        (uint256 _splitBalance, uint256 _warehouseBalance) = _getSplitBalance(_token);

        if (distributeByPush) {
            if (_warehouseBalance > 0) {
                unchecked {
                    _warehouseBalance -= 1;
                }
                _withdrawFromWarehouse(_token, _warehouseBalance);
            }
            pushDistribute(_split, _token, _splitBalance + _warehouseBalance, _distributor);
        } else {
            if (_splitBalance > 0) {
                unchecked {
                    _splitBalance -= 1;
                }
                _depositToWarehouse(_token, _splitBalance);
            }
            pullDistribute(_split, _token, _splitBalance + _warehouseBalance, _distributor);
        }
    }

    /**
     * @notice Distributes the split to the recipients. It distributes the amount of tokens present in Warehouse and the
     * split wallet.
     * @dev The amount of tokens to distribute must be present in the split wallet or the warehouse depending on the
     * distribution direction.
     * @param _split the split struct containing the split data that gets distributed
     * @param _token the token to distribute
     * @param _amount the amount of tokens to distribute
     * @param _distributor the distributor of the split
     */
    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        external
        pausable
    {
        if (splitHash != _split.getHash()) revert InvalidSplit();

        if (distributeByPush) {
            pushDistribute(_split, _token, _amount, _distributor);
        } else {
            pullDistribute(_split, _token, _amount, _distributor);
        }
    }

    /**
     * @notice Deposits tokens to the warehouse
     * @param _token the token to deposit
     * @param _amount the amount of tokens to deposit
     */
    function depositToWarehouse(address _token, uint256 _amount) external {
        _depositToWarehouse(_token, _amount);
    }

    /**
     * @notice Withdraws tokens from the warehouse to the split wallet
     * @param _token the token to withdraw
     */
    function withdrawFromWarehouse(address _token, uint256 _amount) external {
        _withdrawFromWarehouse(_token, _amount);
    }

    /**
     * @notice Gets the total token balance of the split wallet and the warehouse
     * @param _token the token to get the balance of
     * @return _splitBalance the token balance in the split wallet
     * @return _warehouseBalance the token balance in the warehouse of the split wallet
     */
    function getSplitBalance(address _token) public view returns (uint256 _splitBalance, uint256 _warehouseBalance) {
        return _getSplitBalance(_token);
    }

    /* -------------------------------------------------------------------------- */
    /*                         OWNER FUNCTIONS                                    */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Updates the split
     * @dev Only the owner can call this function.
     * @param _split the split struct containing the split data that gets updated
     */
    function updateSplit(SplitV2Lib.Split calldata _split) external onlyOwner {
        // throws error if invalid
        _split.validate();
        splitHash = _split.getHash();
        emit SplitUpdated(owner, _split);
    }

    /**
     * @notice Sets the split distribution direction to be push or pull
     * @dev Only the owner can call this function.
     * @param _distributeByPush whether to distribute by push or pull
     */
    function updateDistributeDirection(bool _distributeByPush) external onlyOwner {
        distributeByPush = _distributeByPush;
        emit DistributeDirectionUpdated(_distributeByPush);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    function _withdrawFromWarehouse(address _token, uint256 _amount) internal {
        SPLITS_WAREHOUSE.withdraw(address(this), _token, _amount);
    }

    function _depositToWarehouse(address _token, uint256 _amount) internal {
        if (_token == NATIVE) {
            SPLITS_WAREHOUSE.deposit{ value: _amount }(address(this), _token, _amount);
        } else {
            if (IERC20(_token).allowance(address(this), address(SPLITS_WAREHOUSE)) < _amount) {
                IERC20(_token).approve(address(SPLITS_WAREHOUSE), type(uint256).max);
            }
            SPLITS_WAREHOUSE.deposit(address(this), _token, _amount);
        }
    }

    function _getSplitBalance(address _token) private view returns (uint256 _splitBalance, uint256 _warehouseBalance) {
        if (_token == NATIVE) {
            _splitBalance = address(this).balance;
            _warehouseBalance = SPLITS_WAREHOUSE.balanceOf(address(this), _token.toUint256());
        } else {
            _splitBalance = _token.balanceOf(address(this));
            _warehouseBalance = SPLITS_WAREHOUSE.balanceOf(address(this), _token.toUint256());
        }
    }

    // assumes the amount is already present in the split wallet
    function pushDistribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        internal
    {
        uint256 numOfRecipients = _split.recipients.length;
        uint256 distributorReward = SplitV2Lib.calculateDistributorReward(_split.distributionIncentive, _amount);
        _amount -= distributorReward;
        uint256 amountDistributed;
        uint256 allocatedAmount;

        if (_token == NATIVE) {
            for (uint256 i = 0; i < numOfRecipients;) {
                allocatedAmount = _amount * _split.allocations[i] / _split.totalAllocation;
                amountDistributed += allocatedAmount;

                if (!_split.recipients[i].trySafeTransferETH(allocatedAmount, SafeTransferLib.GAS_STIPEND_NO_GRIEF)) {
                    SPLITS_WAREHOUSE.deposit{ value: allocatedAmount }(_split.recipients[i], _token, allocatedAmount);
                }
                unchecked {
                    ++i;
                }
            }

            _distributor.safeTransferETH(distributorReward);
        } else {
            for (uint256 i = 0; i < numOfRecipients;) {
                allocatedAmount = _amount * _split.allocations[i] / _split.totalAllocation;
                amountDistributed += allocatedAmount;

                _token.safeTransfer(_split.recipients[i], allocatedAmount);
                unchecked {
                    ++i;
                }
            }

            _token.safeTransfer(_distributor, distributorReward);
        }

        emit SplitDistributed(_token, _distributor, amountDistributed, distributorReward, true);
    }

    // assumes the amount is already deposited to the warehouse
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
        SPLITS_WAREHOUSE.transfer(_distributor, _token.toUint256(), distibutorReward);
        SPLITS_WAREHOUSE.batchTransfer(_token, _split.recipients, amounts);
        emit SplitDistributed(_token, _distributor, amountDistributed, distibutorReward, false);
    }
}
