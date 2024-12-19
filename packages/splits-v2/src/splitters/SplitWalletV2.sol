// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { ISplitsWarehouse } from "../interfaces/ISplitsWarehouse.sol";

import { Cast } from "../libraries/Cast.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { ERC1271 } from "../utils/ERC1271.sol";
import { Wallet } from "../utils/Wallet.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title Split Wallet V2
 * @author Splits
 * @notice Base splitter contract.
 * @dev `SplitProxy` handles `receive()` itself to avoid the gas cost with `DELEGATECALL`.
 */
abstract contract SplitWalletV2 is Wallet, ERC1271 {
    using SplitV2Lib for SplitV2Lib.Split;
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
    event SplitDistributed(address indexed token, address indexed distributor, uint256 amount);

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

    /// @notice the block number at which the split was last updated
    uint256 public updateBlockNumber;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitWarehouse) ERC1271("splitWallet", "2.1") {
        SPLITS_WAREHOUSE = ISplitsWarehouse(_splitWarehouse);
        NATIVE_TOKEN = SPLITS_WAREHOUSE.NATIVE_TOKEN();
        FACTORY = msg.sender;
    }

    /**
     * @notice Initializes the split wallet with a split and its corresponding data.
     * @dev Only the factory can call this function.
     * @param _split The split struct containing the split data that gets initialized.
     */
    function initialize(SplitV2Lib.Split calldata _split, address _owner) external {
        if (msg.sender != FACTORY) revert UnauthorizedInitializer();

        _split.validate();
        splitHash = _split.getHash();
        updateBlockNumber = block.number;
        emit SplitUpdated(_split);

        Wallet.__initWallet(_owner);
    }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function distribute(SplitV2Lib.Split calldata _split, address _token, address _distributor) external virtual;

    function distribute(
        SplitV2Lib.Split calldata _split,
        address _token,
        uint256 _distributeAmount,
        bool _performWarehouseTransfer,
        address _distributor
    )
        external
        virtual;

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
        updateBlockNumber = block.number;
        emit SplitUpdated(_split);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function getSigner() internal view override returns (address) {
        return owner;
    }
}
