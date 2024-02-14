// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/**
 * @title Track user nonces.
 * @dev Inspired by Uniswap's Permit2 UnorderedNonces.
 */
abstract contract UnorderedNonces {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error InvalidNonce();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event NonceInvalidation(address indexed owner, uint256 nonce);

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Mapping of token owner to a specified word to a bitmap.
     * @dev word is capped at type(uint248).max.
     * @dev returns a uint256 bitmap.
     */
    mapping(address account => mapping(uint256 word => uint256 bitMap)) public nonceBitMap;

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Invalidates the nonce for the msg.sender.
     * @dev if the nonce is already invalidated, the function will succeed.
     * @param nonce nonce to invalidate.
     */
    function invalidateNonce(uint256 nonce) external {
        (uint256 word, uint256 bit) = calculateWordAndBit(nonce);

        // flip the bit in the bitmap by taking a bitwise OR.
        // if the bit is already flipped, the result will be the same.
        nonceBitMap[msg.sender][word] |= bit;

        emit NonceInvalidation(msg.sender, nonce);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function useNonce(address _from, uint256 _nonce) internal {
        (uint256 word, uint256 bit) = calculateWordAndBit(_nonce);

        // flip the bit in the bitmap by taking a bitwise XOR.
        uint256 flipped = nonceBitMap[_from][word] ^= bit;

        // check if the bit was already flipped.
        if (flipped & bit == 0) revert InvalidNonce();
    }

    function calculateWordAndBit(uint256 nonce) internal pure returns (uint256 word, uint256 bit) {
        // word is nonce divided by 256.
        word = uint256(nonce) >> 8;

        // bit is 1 shifted left by the nonce modulo 256.
        bit = 1 << uint8(nonce);
    }
}
