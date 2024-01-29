// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

// TODO: do we want to use our clone or the minimal standard?
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
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitCreated(address indexed split, SplitV2Lib.Split splitParams, address owner, address creator);

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
     * @param _splitParams Params to create split with
     * @param _owner Owner of created split
     * @param _creator Creator of created split
     * @param _salt Salt for create2
     */
    function createSplitDeterministic(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        address _creator,
        bytes32 _salt
    )
        external
        returns (address split)
    {
        split = SPLIT_WALLET_IMPLEMENTATION.cloneDeterministic(_getSalt(_splitParams, _owner, _salt));

        SplitWalletV2(split).initialize(_splitParams, _owner);

        emit SplitCreated(split, _splitParams, _owner, _creator);
    }

    /**
     * @notice Create a new split using create
     * @param _splitParams Params to create split with
     * @param _owner Owner of created split
     * @param _creator Creator of created split
     */
    function createSplit(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        address _creator
    )
        external
        returns (address split)
    {
        split = SPLIT_WALLET_IMPLEMENTATION.clone();

        SplitWalletV2(split).initialize(_splitParams, _owner);

        emit SplitCreated(split, _splitParams, _owner, _creator);
    }

    /**
     * @notice Predict the address of a new split
     * @param _splitParams Params to create split with
     * @param _owner Owner of created split
     * @param _salt Salt for create2
     */
    function predictDeterministicAddress(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        bytes32 _salt
    )
        external
        view
        returns (address)
    {
        return _predictDeterministicAddress(_splitParams, _owner, _salt);
    }

    /**
     * @notice Predict the address of a new split and check if it is deployed
     * @param _splitParams Params to create split with
     * @param _owner Owner of created split
     * @param _salt Salt for create2
     */
    function isDeployed(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        bytes32 _salt
    )
        external
        view
        returns (address split, bool exists)
    {
        split = _predictDeterministicAddress(_splitParams, _owner, _salt);
        exists = split.code.length > 0;
    }

    /* -------------------------------------------------------------------------- */
    /*                         PRIVATE/INTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _getSalt(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        bytes32 _salt
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(bytes.concat(abi.encode(_splitParams, _owner), _salt));
    }

    function _predictDeterministicAddress(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        bytes32 _salt
    )
        internal
        view
        returns (address)
    {
        return SPLIT_WALLET_IMPLEMENTATION.predictDeterministicAddress(
            _getSalt(_splitParams, _owner, _salt), address(this)
        );
    }
}
