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
        uint256[] allocations;
        uint256 totalAllocation;
        uint16 pushDistributionIncentive;
        uint16 pullDistributionIncentive;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    uint256 internal constant PERCENTAGE_SCALE = 1e6;

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
        uint256 numOfRecipients = _split.allocations.length;
        if (_split.recipients.length != numOfRecipients) {
            revert InvalidSplit_LengthMismatch();
        }
        uint256 totalAllocation;

        for (uint256 i = 0; i < numOfRecipients;) {
            totalAllocation += _split.allocations[i];
            unchecked {
                ++i;
            }
        }

        if (totalAllocation != _split.totalAllocation) revert InvalidSplit_TotalAllocationMismatch();
    }

    function getDistributionsForPush(
        Split calldata _split,
        uint256 _amount
    )
        internal
        pure
        returns (uint256[] memory amounts, uint256 amountDistributed, uint256 distributorReward)
    {
        uint256 numOfRecipients = _split.recipients.length;
        amounts = new uint256[](numOfRecipients);

        distributorReward = _amount * _split.pushDistributionIncentive / PERCENTAGE_SCALE;

        _amount -= distributorReward;

        for (uint256 i = 0; i < numOfRecipients;) {
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
        uint256 numOfRecipients = _split.recipients.length;
        amounts = new uint256[](numOfRecipients);

        distributorReward = _amount * _split.pullDistributionIncentive / PERCENTAGE_SCALE;

        _amount -= distributorReward;

        for (uint256 i = 0; i < numOfRecipients;) {
            amounts[i] = _amount * _split.allocations[i] / _split.totalAllocation;
            amountDistributed += amounts[i];
            unchecked {
                ++i;
            }
        }
    }
}
