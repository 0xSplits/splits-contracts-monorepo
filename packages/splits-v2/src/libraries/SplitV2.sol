// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

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
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    uint256 internal constant MAX_INCENTIVE = 1e5;
    uint256 internal constant INCENTIVE_SCALE = 1e6;

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function getHash(Split calldata _split) internal pure returns (bytes32) {
        return keccak256(abi.encode(_split));
    }

    function getHashMem(Split memory _split) internal pure returns (bytes32) {
        return keccak256(abi.encode(_split));
    }

    function validate(Split calldata _split) internal pure {
        if (_split.recipients.length != _split.allocations.length) {
            revert InvalidSplit_LengthMismatch();
        }
        uint256 totalAllocation = _split.totalAllocation;

        for (uint256 i = 0; i < _split.recipients.length;) {
            totalAllocation -= _split.allocations[i];
            unchecked {
                ++i;
            }
        }

        if (totalAllocation != 0) revert InvalidSplit_TotalAllocationMismatch();

        if (_split.pushDistributionIncentive > MAX_INCENTIVE) {
            revert InvalidSplit_InvalidIncentive();
        }

        if (_split.pullDistributionIncentive > MAX_INCENTIVE) {
            revert InvalidSplit_InvalidIncentive();
        }
    }

    function getDistributionsForPush(
        Split calldata _split,
        uint256 _amount
    )
        internal
        pure
        returns (uint256[] memory amounts, uint256 amountDistributed, uint256 distributorReward)
    {
        amounts = new uint256[](_split.recipients.length);

        distributorReward = _amount * _split.pushDistributionIncentive / INCENTIVE_SCALE;

        _amount -= distributorReward;

        for (uint256 i = 0; i < _split.recipients.length;) {
            amounts[i] = _amount * _split.allocations[i] / _split.totalAllocation;
            amountDistributed += amounts[i];
            unchecked {
                ++i;
            }
        }
    }

    function getDistributionsForPull(
        Split calldata _split,
        uint256 _amount
    )
        internal
        pure
        returns (uint256[] memory amounts, uint256 amountDistributed, uint256 distributorReward)
    {
        amounts = new uint256[](_split.recipients.length);

        distributorReward = _amount * _split.pullDistributionIncentive / INCENTIVE_SCALE;

        _amount -= distributorReward;

        for (uint256 i = 0; i < _split.recipients.length;) {
            amounts[i] = _amount * _split.allocations[i] / _split.totalAllocation;
            amountDistributed += amounts[i];
            unchecked {
                ++i;
            }
        }
    }
}
