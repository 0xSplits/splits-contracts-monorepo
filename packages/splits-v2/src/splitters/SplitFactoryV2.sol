// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Clone } from "../libraries/Clone.sol";
import { SplitV2Lib } from "../libraries/SplitV2.sol";

import { Nonces } from "../utils/Nonces.sol";
import { SplitWalletV2 } from "./SplitWalletV2.sol";

/**
 * @title SplitFactoryV2
 * @author Splits
 * @notice Minimal smart wallet clone-factory for v2 splitters.
 */
abstract contract SplitFactoryV2 is Nonces {
    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SplitCreated(
        address indexed split, SplitV2Lib.Split splitParams, address owner, address creator, bytes32 salt
    );

    event SplitCreated(address indexed split, SplitV2Lib.Split splitParams, address owner, address creator);

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice address of Split Wallet V2 implementation.
    address public immutable SPLIT_WALLET_IMPLEMENTATION;

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Create a new split using create2.
     * @dev Returns existing split if already created, otherwise creates new split.
     * @param _splitParams Params to create split with.
     * @param _owner Owner of created split.
     * @param _creator Creator of created split.
     * @param _salt Salt for create2.
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
        bytes32 salt = _getSalt({ _splitParams: _splitParams, _owner: _owner, _salt: _salt });

        split = Clone.predictDeterministicAddress({
            _implementation: SPLIT_WALLET_IMPLEMENTATION,
            _salt: salt,
            _deployer: address(this)
        });

        if (split.code.length > 0) {
            return split;
        }

        split = Clone.cloneDeterministic({ _implementation: SPLIT_WALLET_IMPLEMENTATION, _salt: salt });

        SplitWalletV2(split).initialize(_splitParams, _owner);

        emit SplitCreated({ split: split, splitParams: _splitParams, owner: _owner, creator: _creator, salt: _salt });
    }

    /**
     * @notice Create a new split with params and owner.
     * @dev Uses a hash-based incrementing nonce over params and owner.
     * @dev designed to be used with integrating contracts to avoid salt management and needing to handle the potential
     * for griefing via front-running. See docs for more information.
     * @param _splitParams Params to create split with.
     * @param _owner Owner of created split.
     * @param _creator Creator of created split.
     */
    function createSplit(
        SplitV2Lib.Split calldata _splitParams,
        address _owner,
        address _creator
    )
        external
        returns (address split)
    {
        bytes32 hash = keccak256(abi.encode(_splitParams, _owner));

        split = Clone.cloneDeterministic({
            _implementation: SPLIT_WALLET_IMPLEMENTATION,
            _salt: keccak256(bytes.concat(hash, abi.encode(useNonce(hash))))
        });

        SplitWalletV2(split).initialize(_splitParams, _owner);

        emit SplitCreated({ split: split, splitParams: _splitParams, owner: _owner, creator: _creator });
    }

    /**
     * @notice Predict the address of a new split based on split params, owner, and salt.
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
        return _predictDeterministicAddress({ _splitParams: _splitParams, _owner: _owner, _salt: _salt });
    }

    /**
     * @notice Predict the address of a new split based on the nonce of the hash of the params and owner.
     * @param _splitParams Params to create split with.
     * @param _owner Owner of created split.
     */
    function predictDeterministicAddress(
        SplitV2Lib.Split calldata _splitParams,
        address _owner
    )
        external
        view
        returns (address)
    {
        bytes32 hash = keccak256(abi.encode(_splitParams, _owner));
        return Clone.predictDeterministicAddress({
            _implementation: SPLIT_WALLET_IMPLEMENTATION,
            _salt: keccak256(bytes.concat(hash, abi.encode(nonces(hash)))),
            _deployer: address(this)
        });
    }

    /**
     * @notice Predict the address of a new split and check if it is deployed.
     * @param _splitParams Params to create split with.
     * @param _owner Owner of created split.
     * @param _salt Salt for create2.
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
        split = _predictDeterministicAddress({ _splitParams: _splitParams, _owner: _owner, _salt: _salt });
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
        return Clone.predictDeterministicAddress({
            _implementation: SPLIT_WALLET_IMPLEMENTATION,
            _salt: _getSalt({ _splitParams: _splitParams, _owner: _owner, _salt: _salt }),
            _deployer: address(this)
        });
    }
}
