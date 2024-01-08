// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library SplitV2Lib {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidSplit_TotalAllocationMismatch();
    error InvalidSplit_InvalidIncentive();
    error InvalidSplit_LengthMismatch();

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Split struct
     * @dev This struct is used to store the split information
     * @param recipients The recipients of the split
     * @param allocations The allocations of the split
     * @param totalAllocation The total allocation of the split
     * @param pushDistributionIncentive The incentive for push distribution
     * @param pullDistributionIncentive The incentive for pull distribution
     */
    struct Split {
        address[] recipients;
        uint32[] allocations;
        uint256 totalAllocation;
        uint256 pushDistributionIncentive;
        uint256 pullDistributionIncentive;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function getHash(Split calldata _split) internal pure returns (bytes32) {
        return keccak256(abi.encode(_split));
    }

    function validate(Split calldata _split) internal pure {
        if (_split.recipients.length != _split.allocations.length) {
            revert InvalidSplit_LengthMismatch();
        }
        uint256 totalAllocation = _split.totalAllocation;

        for (uint256 i = 0; i < _split.recipients.length; i++) {
            totalAllocation -= _split.allocations[i];
        }

        if (totalAllocation != 0) revert InvalidSplit_TotalAllocationMismatch();

        uint256 maxIncentive = calculateMaxIncentive(_split.totalAllocation);

        if (_split.pushDistributionIncentive > maxIncentive) {
            revert InvalidSplit_InvalidIncentive();
        }

        if (_split.pullDistributionIncentive > maxIncentive) {
            revert InvalidSplit_InvalidIncentive();
        }
    }

    function calculateMaxIncentive(uint256 _totalAllocation) internal pure returns (uint256) {
        return 10 * _totalAllocation / 100;
    }

    function getDistributions(
        Split calldata _split,
        uint256 _amount,
        bool _distributeByPush
    )
        internal
        pure
        returns (uint256[] memory amounts, uint256 distributorReward)
    {
        amounts = new uint256[](_split.recipients.length);

        if (_distributeByPush) {
            distributorReward = scaleAmount(_amount, _split.totalAllocation, _split.pushDistributionIncentive);
        } else {
            distributorReward = scaleAmount(_amount, _split.totalAllocation, _split.pullDistributionIncentive);
        }

        _amount -= distributorReward;

        for (uint256 i = 0; i < _split.recipients.length; i++) {
            amounts[i] = scaleAmount(_amount, _split.totalAllocation, _split.allocations[i]);
        }
    }

    function scaleAmount(
        uint256 _amount,
        uint256 _totalAllocation,
        uint256 _allocation
    )
        internal
        pure
        returns (uint256)
    {
        return _amount * _allocation / _totalAllocation;
    }
}
