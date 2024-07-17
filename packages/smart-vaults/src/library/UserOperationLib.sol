// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IAccount } from "../interfaces/IAccount.sol";

/**
 * @title User operation Library
 * @notice Forked from
 * https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/UserOperationLib.sol
 * @dev Light here refers to the piece of data not related to gas or gas price in the userOp.
 */
library UserOperationLib {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    uint256 public constant VALID_SIGNATURE = 0;

    uint256 public constant INVALID_SIGNATURE = 1;

    /**
     * keccak function over calldata.
     * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than
     * letting solidity do it.
     */
    function calldataKeccak(bytes calldata data) private pure returns (bytes32 ret) {
        assembly ("memory-safe") {
            let mem := mload(0x40)
            let len := data.length
            calldatacopy(mem, data.offset, len)
            ret := keccak256(mem, len)
        }
    }

    /**
     * Get sender from user operation data.
     * @param userOp - The user operation data.
     */
    function getSender(IAccount.PackedUserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /**
     * Pack the light user operation data into bytes for hashing.
     * @param userOp - The user operation data.
     */
    function encodeLight(IAccount.PackedUserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);

        return abi.encode(sender, nonce, hashInitCode, hashCallData);
    }

    /**
     * Hash light user operation data.
     * @param userOp - The user operation data.
     */
    function hashLight(IAccount.PackedUserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(encodeLight(userOp));
    }

    /**
     * Pack the user operation data into bytes for hashing.
     * @param userOp - The user operation data.
     */
    function encode(IAccount.PackedUserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

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
     * @param userOp - The user operation data.
     */
    function hash(IAccount.PackedUserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(encode(userOp));
    }
}
