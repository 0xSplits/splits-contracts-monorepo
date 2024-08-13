// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

/**
 * @title User operation Library
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @notice Forked from
 * https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/UserOperationLib.sol
 * @dev Light here refers to the subset of user op params not related to gas, gas price or initCode in the userOp.
 */
library UserOperationLib {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    uint256 public constant VALID_SIGNATURE = 0;

    uint256 public constant INVALID_SIGNATURE = 1;

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice keccak function over calldata.
     * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than
     * letting solidity do it.
     */
    function calldataKeccak(bytes calldata data_) private pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data_.length
            calldatacopy(mem, data_.offset, len)
            ret := keccak256(mem, len)
        }
    }

    /**
     * @notice Get sender from user operation data.
     * @param userOp_ - The user operation data.
     */
    function getSender(PackedUserOperation calldata userOp_) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp_)
        }
        return address(uint160(data));
    }

    /**
     * @notice Pack the light user operation data into bytes for hashing.
     * @dev Does not include the following properties of the User Op.
     *  - initCode
     *  - accountGasLimits
     *  - preVerificationGas
     *  - gasFees
     *  - paymasterAndData
     *  - signature
     * @param userOp_ - The user operation data.
     */
    function encodeLight(PackedUserOperation calldata userOp_) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp_);
        uint256 nonce = userOp_.nonce;
        bytes32 hashCallData = calldataKeccak(userOp_.callData);

        return abi.encode(sender, nonce, hashCallData);
    }

    /**
     * @notice Hash light user operation data.
     * @param userOp_ - The user operation data.
     */
    function hashLight(PackedUserOperation calldata userOp_) internal pure returns (bytes32) {
        return keccak256(encodeLight(userOp_));
    }

    /**
     * @notice Pack the user operation data into bytes for hashing.
     * @param userOp_ - The user operation data.
     */
    function encode(PackedUserOperation calldata userOp_) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp_);
        uint256 nonce = userOp_.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp_.initCode);
        bytes32 hashCallData = calldataKeccak(userOp_.callData);
        bytes32 accountGasLimits = userOp_.accountGasLimits;
        uint256 preVerificationGas = userOp_.preVerificationGas;
        bytes32 gasFees = userOp_.gasFees;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp_.paymasterAndData);

        // solhint-disable
        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            accountGasLimits,
            preVerificationGas,
            gasFees,
            hashPaymasterAndData
        );
        // solhint-enable
    }

    /**
     * Hash the user operation data.
     * @param userOp_ - The user operation data.
     */
    function hash(PackedUserOperation calldata userOp_) internal pure returns (bytes32) {
        return keccak256(encode(userOp_));
    }
}
