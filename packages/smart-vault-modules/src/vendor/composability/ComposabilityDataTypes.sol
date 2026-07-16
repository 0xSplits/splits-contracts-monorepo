// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// Vendored from bcnmy/composable-batch-erc (MIT) @ 71d43fead3b836ee9cb5cebeac4f96a68bf21dc3.
// Modifications: added the `Execution` struct locally (upstream imports it from erc7579).

/// @notice Where a resolved input routes within the composed call.
enum InputParamType {
    TARGET, // The target address
    VALUE, // The value
    CALL_DATA // The call data
}

/// @notice How an input parameter's value is fetched at execution time.
enum InputParamFetcherType {
    RAW_BYTES, // Already encoded bytes
    STATIC_CALL, // Perform a static call
    BALANCE // Get the balance of an address
}

/// @notice How an output value is fetched for capture.
enum OutputParamFetcherType {
    EXEC_RESULT, // The return of the execution call
    STATIC_CALL // Call to some other function
}

/// @notice Predicate applied to a resolved value.
enum ConstraintType {
    EQ, // Equal to
    GTE, // Greater than or equal to
    LTE, // Less than or equal to
    IN // In range
}

/// @notice Constraint for parameter validation. Constraint `i` validates 32-byte word `i` of the resolved value, so
///         single-word values (balances, static reads) support exactly one constraint.
struct Constraint {
    ConstraintType constraintType;
    bytes referenceData;
}

/// @notice A dynamically resolved input parameter.
struct InputParam {
    InputParamType paramType;
    InputParamFetcherType fetcherType; // How to fetch the parameter
    bytes paramData;
    Constraint[] constraints;
}

/// @notice A captured output written to the Storage contract.
struct OutputParam {
    OutputParamFetcherType fetcherType; // How to fetch the parameter
    bytes paramData;
}

/// @notice A single composable batch entry.
struct ComposableExecution {
    bytes4 functionSig;
    InputParam[] inputParams;
    OutputParam[] outputParams;
}

/// @notice A resolved call ready for execution.
struct Execution {
    address target;
    uint256 value;
    bytes callData;
}
