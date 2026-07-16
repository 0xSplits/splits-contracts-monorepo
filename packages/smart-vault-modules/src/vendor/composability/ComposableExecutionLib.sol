// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC20 } from "src/interfaces/IERC20.sol";
import {
    Constraint,
    ConstraintType,
    Execution,
    InputParam,
    InputParamFetcherType,
    InputParamType,
    OutputParam,
    OutputParamFetcherType
} from "src/vendor/composability/ComposabilityDataTypes.sol";
import { Storage } from "src/vendor/composability/Storage.sol";

// Vendored from bcnmy/composable-batch-erc (MIT) @ 71d43fead3b836ee9cb5cebeac4f96a68bf21dc3.
// Modifications:
// - Imports: `Execution` comes from the local types file (upstream: erc7579) and `IERC20` from
//   src/interfaces/IERC20.sol (upstream: OpenZeppelin).
// - `require(cond, CustomError())` rewritten to `if (!cond) revert ...;` (that require form needs solc >= 0.8.26;
//   this package pins 0.8.23).
// - `EXEC_RESULT` output capture reverts with `ExecResultNotSupported`: SmartVault's `executeFromModule` discards
//   return data, so the module has no execution result to parse. `STATIC_CALL` output capture covers the same use
//   cases by reading post-call state.

// Library for composable execution handling
library ComposableExecutionLib {
    error ConstraintNotMet(ConstraintType constraintType);
    error Output_StaticCallFailed();
    error InvalidParameterEncoding(string message);
    error InvalidOutputParamFetcherType();
    error ComposableExecutionFailed();
    error InvalidConstraintType();
    error InvalidSetOfInputParams(string message);
    error ExecResultNotSupported();

    // Process the input parameters and return the composed calldata
    function processInputs(
        InputParam[] calldata inputParams,
        bytes4 functionSig
    )
        internal
        view
        returns (Execution memory)
    {
        address composedTarget;
        uint256 composedValue;
        bytes memory composedCalldata = abi.encodePacked(functionSig);
        uint256 length = inputParams.length;

        // Bit 0: TARGET param type set, Bit 1: VALUE param type set
        uint256 paramTypeFlags = 0;
        for (uint256 i; i < length; i++) {
            bytes memory processedInput = processInput(inputParams[i]);
            if (inputParams[i].paramType == InputParamType.TARGET) {
                if (inputParams[i].fetcherType == InputParamFetcherType.BALANCE) {
                    revert InvalidParameterEncoding("BALANCE fetcher type is not supported for TARGET param type");
                }
                // Check if TARGET has already been set (bit 0)
                if (paramTypeFlags & 1 != 0) {
                    revert InvalidSetOfInputParams("TARGET param type can only be set once");
                }
                paramTypeFlags |= 1; // Set bit 0
                composedTarget = abi.decode(processedInput, (address));
            } else if (inputParams[i].paramType == InputParamType.VALUE) {
                // Check if VALUE has already been set (bit 1)
                if (paramTypeFlags & 2 != 0) {
                    revert InvalidSetOfInputParams("VALUE param type can only be set once");
                }
                paramTypeFlags |= 2; // Set bit 1
                composedValue = abi.decode(processedInput, (uint256));
            } else if (inputParams[i].paramType == InputParamType.CALL_DATA) {
                composedCalldata = bytes.concat(composedCalldata, processedInput);
            } else {
                revert InvalidParameterEncoding("Invalid param type");
            }
        }
        // if a param with TARGET type was not provided, it will be address(0)
        // we don't restrict it since some calls may want to call address(0)
        // if a param with VALUE type was not provided, it will be 0
        // this is even more often case, as many calls happen with 0 value
        return Execution({ target: composedTarget, value: composedValue, callData: composedCalldata });
    }

    // Process a single input parameter and return the composed calldata
    function processInput(InputParam calldata param) internal view returns (bytes memory) {
        if (param.fetcherType == InputParamFetcherType.RAW_BYTES) {
            _validateConstraints(param.paramData, param.constraints);
            return param.paramData;
        } else if (param.fetcherType == InputParamFetcherType.STATIC_CALL) {
            address contractAddr;
            bytes calldata callData;
            bytes calldata paramData = param.paramData;
            // expect paramData to be abi.encode(address contractAddr, bytes callData)
            assembly {
                contractAddr := calldataload(paramData.offset)
                let s := calldataload(add(paramData.offset, 0x20))
                let u := add(paramData.offset, s)
                callData.offset := add(u, 0x20)
                callData.length := calldataload(u)
            }
            (bool success, bytes memory returnData) = contractAddr.staticcall(callData);
            if (!success) {
                revert ComposableExecutionFailed();
            }
            _validateConstraints(returnData, param.constraints);
            return returnData;
        } else if (param.fetcherType == InputParamFetcherType.BALANCE) {
            address tokenAddr;
            address account;
            bytes calldata paramData = param.paramData;

            // expect paramData to be abi.encodePacked(address token, address account)
            // Validate exact length requirement
            if (paramData.length != 40) {
                revert InvalidParameterEncoding("Invalid paramData length");
            }
            assembly {
                tokenAddr := shr(96, calldataload(paramData.offset))
                account := shr(96, calldataload(add(paramData.offset, 0x14)))
            }

            uint256 balance;
            if (tokenAddr == address(0)) {
                balance = account.balance;
            } else {
                balance = IERC20(tokenAddr).balanceOf(account);
            }
            _validateConstraints(abi.encode(balance), param.constraints);
            return abi.encode(balance);
        } else {
            revert InvalidParameterEncoding("Invalid param fetcher type");
        }
    }

    // Process the output parameters
    function processOutputs(OutputParam[] calldata outputParams, bytes memory returnData, address account) internal {
        uint256 length = outputParams.length;
        for (uint256 i; i < length; i++) {
            processOutput(outputParams[i], returnData, account);
        }
    }

    // Process a single output parameter and write to storage
    function processOutput(OutputParam calldata param, bytes memory, address account) internal {
        // only static types are supported for now as return values
        // can also process all the static return values which are before the first dynamic return value in the
        // returnData
        if (param.fetcherType == OutputParamFetcherType.EXEC_RESULT) {
            revert ExecResultNotSupported();
        } else if (param.fetcherType == OutputParamFetcherType.STATIC_CALL) {
            uint256 returnValues;
            address sourceContract;
            bytes calldata sourceCallData;
            address targetStorageContract;
            bytes32 targetStorageSlot;
            bytes calldata paramData = param.paramData;
            assembly {
                returnValues := calldataload(paramData.offset)
                sourceContract := calldataload(add(paramData.offset, 0x20))
                let s := calldataload(add(paramData.offset, 0x40))
                let u := add(paramData.offset, s)
                sourceCallData.offset := add(u, 0x20)
                sourceCallData.length := calldataload(u)
                targetStorageContract := calldataload(add(paramData.offset, 0x60))
                targetStorageSlot := calldataload(add(paramData.offset, 0x80))
            }
            (bool outputSuccess, bytes memory outputReturnData) = sourceContract.staticcall(sourceCallData);
            if (!outputSuccess) {
                revert Output_StaticCallFailed();
            }
            _parseReturnDataAndWriteToStorage(
                returnValues, outputReturnData, targetStorageContract, targetStorageSlot, account
            );
        } else {
            revert InvalidOutputParamFetcherType();
        }
    }

    /// @dev Validate the constraints => compare the value with the reference data
    function _validateConstraints(bytes memory rawValue, Constraint[] calldata constraints) private pure {
        if (constraints.length > 0) {
            for (uint256 i; i < constraints.length; i++) {
                Constraint memory constraint = constraints[i];
                bytes32 returnValue;
                assembly {
                    returnValue := mload(add(rawValue, add(0x20, mul(i, 0x20))))
                }
                if (constraint.constraintType == ConstraintType.EQ) {
                    if (returnValue != bytes32(constraint.referenceData)) {
                        revert ConstraintNotMet(ConstraintType.EQ);
                    }
                } else if (constraint.constraintType == ConstraintType.GTE) {
                    if (returnValue < bytes32(constraint.referenceData)) {
                        revert ConstraintNotMet(ConstraintType.GTE);
                    }
                } else if (constraint.constraintType == ConstraintType.LTE) {
                    if (returnValue > bytes32(constraint.referenceData)) {
                        revert ConstraintNotMet(ConstraintType.LTE);
                    }
                } else if (constraint.constraintType == ConstraintType.IN) {
                    (bytes32 lowerBound, bytes32 upperBound) = abi.decode(constraint.referenceData, (bytes32, bytes32));
                    if (returnValue < lowerBound || returnValue > upperBound) {
                        revert ConstraintNotMet(ConstraintType.IN);
                    }
                } else {
                    revert InvalidConstraintType();
                }
            }
        }
    }

    /// @dev Parse the return data and write to the appropriate storage contract
    function _parseReturnDataAndWriteToStorage(
        uint256 returnValues,
        bytes memory returnData,
        address targetStorageContract,
        bytes32 targetStorageSlot,
        address account
    )
        internal
    {
        for (uint256 i; i < returnValues; i++) {
            bytes32 value;
            assembly {
                value := mload(add(returnData, add(0x20, mul(i, 0x20))))
            }
            Storage(targetStorageContract)
                .writeStorage({
                slot: keccak256(abi.encodePacked(targetStorageSlot, i)), value: value, account: account
            });
        }
    }
}
