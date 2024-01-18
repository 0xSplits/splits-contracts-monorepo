// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { Clone } from "../libraries/Clone.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";
import { SplitWalletV2 } from "./SplitWalletV2.sol";

/**
 * @title SplitFactoryV2
 * @author Splits
 * @notice Minimal smart wallet clone-factory for v2 splitters
 */
contract SplitFactoryV2 {
    using Clone for address;

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error ZeroAddress();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitCreated(address indexed split, CreateSplitParams _split);

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCT                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice CreateSplitParams
     * @param split Split struct
     * @param owner Owner of the split
     * @param creator Creator of the split
     */
    struct CreateSplitParams {
        SplitV2Lib.Split split;
        address owner;
        address creator;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice address of Split Wallet V2 implementation
    address public immutable SPLIT_WALLET_IMPLEMENTATION;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Construct a new SplitFactoryV2
     * @param _splitsWarehouse Address of Split Warehouse
     */
    constructor(address _splitsWarehouse) {
        SPLIT_WALLET_IMPLEMENTATION = address(new SplitWalletV2(_splitsWarehouse));
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Create a new split using create2
     * @param _createSplitParams CreateSplitParams struct
     * @param _salt Salt for create2
     */
    function createSplitDeterministic(
        CreateSplitParams calldata _createSplitParams,
        bytes32 _salt
    )
        external
        returns (address split)
    {
        split = SPLIT_WALLET_IMPLEMENTATION.cloneDeterministic(_getSalt(_createSplitParams, _salt));

        SplitWalletV2(split).initialize(_createSplitParams.split, _createSplitParams.owner);

        emit SplitCreated(split, _createSplitParams);
    }

    /**
     * @notice Create a new split using create
     * @param _createSplitParams CreateSplitParams struct
     */
    function createSplit(CreateSplitParams calldata _createSplitParams) external returns (address split) {
        split = SPLIT_WALLET_IMPLEMENTATION.clone();

        SplitWalletV2(split).initialize(_createSplitParams.split, _createSplitParams.owner);

        emit SplitCreated(split, _createSplitParams);
    }

    /**
     * @notice Predict the address of a new split
     * @param _createSplitParams CreateSplitParams struct
     * @param _salt Salt for create2
     */
    function predictDeterministicAddress(
        CreateSplitParams calldata _createSplitParams,
        bytes32 _salt
    )
        external
        view
        returns (address)
    {
        return _predictDeterministicAddress(_createSplitParams, _salt);
    }

    /**
     * @notice Predict the address of a new split and check if it is deployed
     * @param _createSplitParams CreateSplitParams struct
     * @param _salt Salt for create2
     */
    function isDeployed(
        CreateSplitParams calldata _createSplitParams,
        bytes32 _salt
    )
        external
        view
        returns (address split, bool)
    {
        split = _predictDeterministicAddress(_createSplitParams, _salt);
        return (split, split.code.length > 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                         PRIVATE/INTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _getSalt(CreateSplitParams calldata _createSplitParams, bytes32 _salt) internal pure returns (bytes32) {
        return keccak256(bytes.concat(abi.encode(_createSplitParams), _salt));
    }

    function _predictDeterministicAddress(
        CreateSplitParams calldata _createSplitParams,
        bytes32 _salt
    )
        internal
        view
        returns (address)
    {
        return
            SPLIT_WALLET_IMPLEMENTATION.predictDeterministicAddress(_getSalt(_createSplitParams, _salt), address(this));
    }
}
