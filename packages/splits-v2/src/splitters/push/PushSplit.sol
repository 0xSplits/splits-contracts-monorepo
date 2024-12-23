// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitV2Lib } from "../../libraries/SplitV2.sol";
import { SplitWalletV2 } from "../SplitWalletV2.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title Push Split Wallet
 * @author Splits
 * @notice The implementation logic for a splitter that distributes directly to the recipients.
 * @dev `SplitProxy` handles `receive()` itself to avoid the gas cost with `DELEGATECALL`.
 */
contract PushSplit is SplitWalletV2 {
    using SplitV2Lib for SplitV2Lib.Split;
    using SafeERC20 for IERC20;
    using SafeTransferLib for address;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse) SplitWalletV2(_splitWarehouse) { }

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
    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        address _distributor
    )
        external
        override
        pausable
    {
        if (splitHash != _split.getHash()) revert InvalidSplit();

        (uint256 splitBalance, uint256 warehouseBalance) = getSplitBalance(_token);

        if (warehouseBalance > 1) withdrawFromWarehouse(_token);

        // @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // splitBalance -= uint(splitBalance > 0);
            splitBalance := sub(splitBalance, iszero(iszero(splitBalance)))
            // warehouseBalance -= uint(warehouseBalance > 0);
            warehouseBalance := sub(warehouseBalance, iszero(iszero(warehouseBalance)))
        }

        _distribute({
            _split: _split,
            _token: _token,
            _amount: warehouseBalance + splitBalance,
            _distributor: _distributor
        });
    }

    /**
     * @notice Distributes a specific amount of tokens in the split & Warehouse to the recipients.
     * @dev The split must be initialized and the hash of _split must match splitHash.
     * @dev Will revert if the amount of tokens to transfer or distribute doesn't exist.
     * @param _split The split struct containing the split data that gets distributed.
     * @param _token The token to distribute.
     * @param _distributeAmount The amount of tokens to distribute.
     * @param _performWarehouseTransfer if true, withdraws all but 1 amount of tokens from the warehouse.
     * @param _distributor The distributor of the split.
     */
    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _distributeAmount,
        bool _performWarehouseTransfer,
        address _distributor
    )
        external
        override
        pausable
    {
        if (splitHash != _split.getHash()) revert InvalidSplit();

        if (_performWarehouseTransfer) withdrawFromWarehouse(_token);

        _distribute({ _split: _split, _token: _token, _amount: _distributeAmount, _distributor: _distributor });
    }

    /**
     * @notice Withdraws tokens from the warehouse to the split wallet.
     * @param _token The token to withdraw.
     */
    function withdrawFromWarehouse(address _token) public {
        SPLITS_WAREHOUSE.withdraw(address(this), _token);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    /// @dev Assumes the amount is already present in the split wallet.
    function _distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        internal
    {
        uint256 allocatedAmount;
        uint256 numOfRecipients = _split.recipients.length;

        uint256 distributorReward = _split.calculateDistributorReward(_amount);

        uint256 amountToDistribute = _amount - distributorReward;

        if (_token == NATIVE_TOKEN) {
            for (uint256 i; i < numOfRecipients; ++i) {
                allocatedAmount = _split.calculateAllocatedAmount(amountToDistribute, i);

                if (!_split.recipients[i].trySafeTransferETH(allocatedAmount, SafeTransferLib.GAS_STIPEND_NO_GRIEF)) {
                    SPLITS_WAREHOUSE.deposit{ value: allocatedAmount }(_split.recipients[i], _token, allocatedAmount);
                }
            }

            if (distributorReward > 0) _distributor.safeTransferETH(distributorReward);
        } else {
            for (uint256 i; i < numOfRecipients; ++i) {
                allocatedAmount = _split.calculateAllocatedAmount(amountToDistribute, i);

                IERC20(_token).safeTransfer(_split.recipients[i], allocatedAmount);
            }

            if (distributorReward > 0) IERC20(_token).safeTransfer(_distributor, distributorReward);
        }

        emit SplitDistributed({ token: _token, distributor: _distributor, amount: _amount });
    }
}
