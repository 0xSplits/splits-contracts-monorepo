// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Cast } from "../../libraries/Cast.sol";
import { SplitV2Lib } from "../../libraries/SplitV2.sol";
import { SplitWalletV2 } from "../SplitWalletV2.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title Pull Split Wallet
 * @author Splits
 * @notice The implementation logic for a splitter that distributes using the splits warehouse.
 * @dev `SplitProxy` handles `receive()` itself to avoid the gas cost with `DELEGATECALL`.
 */
contract PullSplit is SplitWalletV2 {
    using SplitV2Lib for SplitV2Lib.Split;
    using SafeERC20 for IERC20;
    using Cast for address;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse) SplitWalletV2(_splitWarehouse) { }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Distributes the tokens in the split & Warehouse to the recipients through the warehouse.
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

        // @solidity memory-safe-assembly
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // splitBalance -= uint(splitBalance > 0);
            splitBalance := sub(splitBalance, iszero(iszero(splitBalance)))
            // warehouseBalance -= uint(warehouseBalance > 0);
            warehouseBalance := sub(warehouseBalance, iszero(iszero(warehouseBalance)))
        }

        if (splitBalance > 0) _depositToWarehouse(_token, splitBalance);

        _distribute({
            _split: _split,
            _token: _token,
            _amount: warehouseBalance + splitBalance,
            _distributor: _distributor
        });
    }

    /**
     * @notice Distributes a specific amount of tokens in the split & Warehouse to the recipients through the warehouse.
     * @dev The split must be initialized and the hash of _split must match splitHash.
     * @dev Will revert if the amount of tokens to transfer or distribute doesn't exist.
     * @param _split The split struct containing the split data that gets distributed.
     * @param _token The token to distribute.
     * @param _distributeAmount The amount of tokens to distribute.
     * @param _performWarehouseTransfer if true, deposits all but 1 amount of tokens to the warehouse.
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

        if (_performWarehouseTransfer) {
            uint256 amount =
                (_token == NATIVE_TOKEN ? address(this).balance : IERC20(_token).balanceOf(address(this))) - 1;
            _depositToWarehouse(_token, amount);
        }

        _distribute({ _split: _split, _token: _token, _amount: _distributeAmount, _distributor: _distributor });
    }

    /**
     * @notice Deposits tokens to the warehouse.
     * @param _token The token to deposit.
     * @param _amount The amount of tokens to deposit
     */
    function depositToWarehouse(address _token, uint256 _amount) external pausable {
        _depositToWarehouse(_token, _amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                              INTERNAL/PRIVATE                              */
    /* -------------------------------------------------------------------------- */

    function _depositToWarehouse(address _token, uint256 _amount) internal {
        if (_token == NATIVE_TOKEN) {
            SPLITS_WAREHOUSE.deposit{ value: _amount }({ receiver: address(this), token: _token, amount: _amount });
        } else {
            // solhint-disable-next-line no-empty-blocks
            try SPLITS_WAREHOUSE.deposit({ receiver: address(this), token: _token, amount: _amount }) { }
            catch {
                IERC20(_token).forceApprove({ spender: address(SPLITS_WAREHOUSE), value: type(uint256).max });
                SPLITS_WAREHOUSE.deposit({ receiver: address(this), token: _token, amount: _amount });
            }
        }
    }

    /// @dev Assumes the amount is already deposited to the warehouse.
    function _distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _amount,
        address _distributor
    )
        internal
    {
        (uint256[] memory amounts, uint256 distributorReward) = _split.getDistributions(_amount);

        SPLITS_WAREHOUSE.batchTransfer({ receivers: _split.recipients, token: _token, amounts: amounts });

        if (distributorReward > 0) {
            SPLITS_WAREHOUSE.transfer({ receiver: _distributor, id: _token.toUint256(), amount: distributorReward });
        }

        emit SplitDistributed({ token: _token, distributor: _distributor, amount: _amount });
    }
}
