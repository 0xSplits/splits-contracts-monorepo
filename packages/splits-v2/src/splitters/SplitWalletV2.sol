// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { IWarehouse } from "../interfaces/IWarehouse.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { Wallet } from "../utils/Wallet.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title SplitWalletV2
 * @author splits
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
    error DistributionsPaused();
    error InvalidSplit();
    error ZeroAddress();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitUpdated(address indexed _controller, SplitV2Lib.Split _split);
    event SplitDistributionsPaused(bool _paused);
    event SplitDistributeByPush(bool _distributeByPush);
    event SplitDistributed(address indexed _token, uint256 _amount, address _distributor);

    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    /// @notice address of Split Warehouse
    IWarehouse public immutable SPLIT_WAREHOUSE;

    /// @notice address of Split Wallet V2 factory
    address public immutable FACTORY;

    /// @notice address of native token
    address public immutable NATIVE;

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice the split hash - Keccak256 hash of the split struct
    bytes32 public splitHash;

    /// @notice Controls the distribution of the split
    bool public distributionsPaused;

    /// @notice Controls the distribution direction of the split
    bool public distributeByPush;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse, address _factory) {
        if (_factory == address(0)) revert ZeroAddress();
        SPLIT_WAREHOUSE = IWarehouse(_splitWarehouse);
        NATIVE = SPLIT_WAREHOUSE.NATIVE_TOKEN();
        FACTORY = _factory;
    }

    /**
     * @notice Initializes the split wallet with a split and its corresponding data.
     * @dev Only the factory can call this function. By default, the distribution direction is push and distributions
     * are unpaused.
     * @param split the split struct containing the split data that gets initialized
     */
    function initialize(SplitV2Lib.Split calldata split, address _controller) external {
        if (msg.sender != FACTORY) revert UnauthorizedInitializer();

        // throws error if invalid
        split.validate();
        splitHash = split.getHash();
        emit SplitUpdated(_controller, split);

        Wallet.__initWallet(_controller);
    }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function distributeERC20(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        external
        returns (uint256[] memory amounts, uint256 amountDistributed, uint256 distibutorReward)
    {
        if (distributionsPaused) revert DistributionsPaused();
        if (splitHash != _split.getHash()) revert InvalidSplit();

        if (distributeByPush) {
            (amounts, amountDistributed, distibutorReward) = _split.getDistributionsForPush(_amount);
            for (uint256 i = 0; i < _split.recipients.length; i++) {
                IERC20(_token).safeTransfer(_split.recipients[i], amounts[i]);
            }
        } else {
            (amounts, amountDistributed, distibutorReward) = _split.getDistributionsForPull(_amount);
            IERC20(_token).safeTransfer(address(SPLIT_WAREHOUSE), amountDistributed);
            SPLIT_WAREHOUSE.depositAfterTransfer(_split.recipients, _token, amounts);
        }

        if (distibutorReward > 0) {
            IERC20(_token).safeTransfer(_distributor, distibutorReward);
        }

        emit SplitDistributed(_token, amountDistributed + distibutorReward, _distributor);
    }

    function distributeNative(
        SplitV2Lib.Split calldata _split,
        uint256 _amount,
        address _distributor
    )
        external
        payable
        returns (uint256[] memory amounts, uint256 amountDistributed, uint256 distibutorReward)
    {
        if (distributionsPaused) revert DistributionsPaused();
        if (splitHash != _split.getHash()) revert InvalidSplit();

        if (distributeByPush) {
            (amounts, amountDistributed, distibutorReward) = _split.getDistributionsForPush(_amount);
            for (uint256 i = 0; i < _split.recipients.length; i++) {
                payable(_split.recipients[i]).sendValue(amounts[i]);
            }
        } else {
            (amounts, amountDistributed, distibutorReward) = _split.getDistributionsForPull(_amount);
            SPLIT_WAREHOUSE.deposit{ value: amountDistributed }(_split.recipients, NATIVE, amounts);
        }

        if (distibutorReward > 0) {
            payable(_distributor).sendValue(distibutorReward);
        }

        emit SplitDistributed(NATIVE, amountDistributed + distibutorReward, _distributor);
    }

    /* -------------------------------------------------------------------------- */
    /*                         CONTROLLER/OWNER FUNCTIONS                         */
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
     * @notice Sets the split distributions to be paused or unpaused
     * @dev Only the controller can call this function.
     * @param _pause whether to pause or unpause the split distributions
     */
    function pauseDistributions(bool _pause) external onlyOwner {
        distributionsPaused = _pause;
        emit SplitDistributionsPaused(_pause);
    }

    /**
     * @notice Sets the split distribution direction to be push or pull
     * @dev Only the controller can call this function.
     * @param _distributeByPush whether to distribute by push or pull
     */
    function updateDistributeByPush(bool _distributeByPush) external onlyOwner {
        distributeByPush = _distributeByPush;
        emit SplitDistributeByPush(_distributeByPush);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */
}
