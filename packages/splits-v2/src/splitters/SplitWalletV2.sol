// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { ISplitsWarehouse } from "../interfaces/ISplitsWarehouse.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { Wallet } from "../utils/Wallet.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title SplitWalletV2
 * @author Splits
 * @notice The implementation logic for v2 splitters.
 * @dev `SplitProxy` handles `receive()` itself to avoid the gas cost with `DELEGATECALL`.
 */
contract SplitWalletV2 is Wallet {
    using SplitV2Lib for SplitV2Lib.Split;
    using SafeERC20 for IERC20;
    using Address for address payable;

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
    event SplitDistributeByPush(bool _distributeByPush);
    event SplitDistributed(address indexed _token, uint256 _amount, address _distributor, bool _distributeByPush);

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
     * @notice Distributes the token to the recipients according to the split
     * @dev The token must be approved to the Splits Warehouse before calling this function. Owner can bypass the paused
     * state.
     * @param _split the split struct containing the split data that gets distributed
     * @param _token the token to distribute
     * @param _amount the amount of token to distribute
     * @param _distributor the distributor of the split
     */
    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        external
        payable
        pausable
    {
        if (splitHash != _split.getHash()) revert InvalidSplit();
        if (distributeByPush) {
            return pushDistribute(_split, _token, _amount, _distributor);
        } else {
            return pullDistribute(_split, _token, _amount, _distributor);
        }
    }

    /**
     * @notice Approves the Splits Warehouse to spend the token
     * @param _token the token to approve
     */
    function approveSplitsWarehouse(address _token) external {
        IERC20(_token).approve(address(SPLITS_WAREHOUSE), type(uint256).max);
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
    function updateDistributeByPush(bool _distributeByPush) external onlyOwner {
        distributeByPush = _distributeByPush;
        emit SplitDistributeByPush(_distributeByPush);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

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

                payable(_split.recipients[i]).sendValue(allocatedAmount);
                unchecked {
                    ++i;
                }
            }

            payable(_distributor).sendValue(distributorReward);
        } else {
            for (uint256 i = 0; i < numOfRecipients;) {
                allocatedAmount = _amount * _split.allocations[i] / _split.totalAllocation;
                amountDistributed += allocatedAmount;

                IERC20(_token).safeTransfer(_split.recipients[i], allocatedAmount);
                unchecked {
                    ++i;
                }
            }

            IERC20(_token).safeTransfer(_distributor, distributorReward);
        }

        emit SplitDistributed(_token, amountDistributed + distributorReward, _distributor, true);
    }

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
        if (_token == NATIVE) {
            SPLITS_WAREHOUSE.deposit{ value: amountDistributed }(address(this), _token, amountDistributed);
            payable(_distributor).sendValue(distibutorReward);
        } else {
            SPLITS_WAREHOUSE.deposit(address(this), _token, amountDistributed);
            IERC20(_token).safeTransfer(_distributor, distibutorReward);
        }
        SPLITS_WAREHOUSE.batchTransfer(_token, _split.recipients, amounts);
        emit SplitDistributed(_token, amountDistributed + distibutorReward, _distributor, false);
    }
}
