#!/bin/bash

# Verify Split contracts on specified chain
# This script verifies deployed PullSplit, PullSplitFactory, PushSplit, and PushSplitFactory contracts using Etherscan, Sourcify, or Blockscout
#
# IMPORTANT: This script must be run from the packages/splits-v2 directory
# Usage: ./script/verify-contract.sh <chain_id> [verifier]
# Example: ./script/verify-contract.sh 1 etherscan (for mainnet with etherscan)
# Example: ./script/verify-contract.sh 10 (for optimism with sourcify - default)
# Example: ./script/verify-contract.sh 137 sourcify (for polygon with sourcify)
# Example: ./script/verify-contract.sh 360 blockscout@https://shapescan.xyz/api/ (for shape with blockscout)

set -e  # Exit on any error

# Check if chain parameter is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <chain_id> [verifier]"
    echo "Example: $0 1 etherscan (for mainnet with etherscan)"
    echo "Example: $0 10 (for optimism with sourcify - default)"
    echo "Example: $0 137 sourcify (for polygon with sourcify)"
    echo "Example: $0 360 blockscout@https://shapescan.xyz/api/ (for shape with blockscout)"
    echo ""
    echo "NOTE: This script must be run from the packages/splits-v2 directory"
    echo "Run: ./script/verify-contract.sh <chain_id> [verifier]"
    exit 1
fi

CHAIN_ID=$1
VERIFIER_ARG=${2:-sourcify}  # Default to sourcify if no second argument

# Parse verifier argument to extract verifier type and URL
if [[ "$VERIFIER_ARG" == *"@"* ]]; then
    # Split on @ to get verifier and URL
    VERIFIER=$(echo "$VERIFIER_ARG" | cut -d'@' -f1)
    VERIFIER_URL=$(echo "$VERIFIER_ARG" | cut -d'@' -f2)
else
    VERIFIER="$VERIFIER_ARG"
    VERIFIER_URL=""
fi

# Check if we're in the right directory (should have src/ directory and foundry.toml)
if [ ! -d "src" ] || [ ! -f "foundry.toml" ]; then
    echo "Error: This script must be run from the packages/splits-v2 directory"
    echo "Current directory: $(pwd)"
    echo "Please cd to packages/splits-v2 and run: ./script/verify-contract.sh <chain_id> [verifier]"
    exit 1
fi

# Source environment variables
if [ -f .env ]; then
    source .env
else
    echo "Error: .env file not found in $(pwd)"
    echo "Please create a .env file in the packages/splits-v2 directory"
    exit 1
fi

# Check if ETHERSCAN_API_KEY is set only when using etherscan
if [ "$VERIFIER" = "etherscan" ] && [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Error: ETHERSCAN_API_KEY is not set in .env file"
    echo "ETHERSCAN_API_KEY is required when using etherscan verifier"
    exit 1
fi

# Set verifier arguments based on verifier type
if [ "$VERIFIER" = "etherscan" ]; then
    VERIFIER_ARGS="--verifier etherscan --verifier-api-key $ETHERSCAN_API_KEY --etherscan-api-key $ETHERSCAN_API_KEY"
    CHAIN_ARGS="--chain $CHAIN_ID"
elif [ "$VERIFIER" = "blockscout" ]; then
    if [ -z "$VERIFIER_URL" ]; then
        echo "Error: blockscout verifier requires a URL"
        echo "Usage: blockscout@https://example.com/api/"
        exit 1
    fi
    VERIFIER_ARGS="--verifier blockscout --verifier-url '$VERIFIER_URL'"
    CHAIN_ARGS=""  # blockscout doesn't use --chain parameter
else
    VERIFIER_ARGS="--verifier sourcify"
    CHAIN_ARGS="--chain $CHAIN_ID"
fi

echo "Verifying Split contracts on chain $CHAIN_ID using $VERIFIER..."

echo "1. Verifying PullSplit contract..."
echo "Command: forge verify-contract 0x98254AeDb6B2c30b70483064367f0BA24ca86244 src/splitters/pull/PullSplit.sol:PullSplit $CHAIN_ARGS --via-ir --num-of-optimizations 5000000 $VERIFIER_ARGS --evm-version shanghai --watch --constructor-args \$(cast abi-encode \"constructor(address)\" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)"
forge verify-contract 0x98254AeDb6B2c30b70483064367f0BA24ca86244 \
    src/splitters/pull/PullSplit.sol:PullSplit \
    $CHAIN_ARGS \
    --via-ir \
    --num-of-optimizations 5000000 \
    $VERIFIER_ARGS \
    --evm-version shanghai \
    --watch \
    --constructor-args $(cast abi-encode "constructor(address)" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)

echo "2. Verifying PullSplitFactory contract..."
echo "Command: forge verify-contract 0x6B9118074aB15142d7524E8c4ea8f62A3Bdb98f1 src/splitters/pull/PullSplitFactory.sol:PullSplitFactory $CHAIN_ARGS --via-ir --num-of-optimizations 5000000 $VERIFIER_ARGS --evm-version shanghai --watch --constructor-args \$(cast abi-encode \"constructor(address)\" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)"
forge verify-contract 0x6B9118074aB15142d7524E8c4ea8f62A3Bdb98f1 \
    src/splitters/pull/PullSplitFactory.sol:PullSplitFactory \
    $CHAIN_ARGS \
    --via-ir \
    --num-of-optimizations 5000000 \
    $VERIFIER_ARGS \
    --evm-version shanghai \
    --watch \
    --constructor-args $(cast abi-encode "constructor(address)" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)

echo "3. Verifying PushSplit contract..."
echo "Command: forge verify-contract 0x1e2086A7e84a32482ac03000D56925F607CCB708 src/splitters/push/PushSplit.sol:PushSplit $CHAIN_ARGS --via-ir --num-of-optimizations 5000000 $VERIFIER_ARGS --evm-version shanghai --watch --constructor-args \$(cast abi-encode \"constructor(address)\" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)"
forge verify-contract 0x1e2086A7e84a32482ac03000D56925F607CCB708 \
    src/splitters/push/PushSplit.sol:PushSplit \
    $CHAIN_ARGS \
    --via-ir \
    --num-of-optimizations 5000000 \
    $VERIFIER_ARGS \
    --evm-version shanghai \
    --watch \
    --constructor-args $(cast abi-encode "constructor(address)" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)

echo "4. Verifying PushSplitFactory contract..."
echo "Command: forge verify-contract 0x8E8eB0cC6AE34A38B67D5Cf91ACa38f60bc3Ecf4 src/splitters/push/PushSplitFactory.sol:PushSplitFactory $CHAIN_ARGS --via-ir --num-of-optimizations 5000000 $VERIFIER_ARGS --evm-version shanghai --watch --constructor-args \$(cast abi-encode \"constructor(address)\" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)"
forge verify-contract 0x8E8eB0cC6AE34A38B67D5Cf91ACa38f60bc3Ecf4 \
    src/splitters/push/PushSplitFactory.sol:PushSplitFactory \
    $CHAIN_ARGS \
    --via-ir \
    --num-of-optimizations 5000000 \
    $VERIFIER_ARGS \
    --evm-version shanghai \
    --watch \
    --constructor-args $(cast abi-encode "constructor(address)" 0x8fb66F38cF86A3d5e8768f8F1754A24A6c661Fb8)

echo "All contract verifications completed for chain $CHAIN_ID using $VERIFIER!"