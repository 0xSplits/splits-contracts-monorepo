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

    event NonceInvalidation(address indexed owner, uint256 word, uint256 bitMap);

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
     * @notice Invalidates the bits specified in mask for the bitmap at the word position.
     * @dev The word is maxed at type(uint248).max.
     * @param _word A number to index the nonceBitmap at.
     * @param _mask A bitmap masked against msg.sender's current bitmap at the word position.
     */
    function invalidateNonces(uint256 _word, uint256 _mask) external {
        nonceBitMap[msg.sender][_word] |= _mask;

        emit NonceInvalidation(msg.sender, _word, _mask);
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function useNonce(address from, uint256 nonce) internal {
        // word is nonce divided by 256.
        uint256 word = uint256(nonce) >> 8;

        // bitMap is nonce modulo 256.
        uint256 bitMap = uint8(nonce);

        // bit is 1 shifted left by the bitMap.
        uint256 bit = 1 << bitMap;

        // flip the bit in the bitmap by taking a bitwise XOR.
        uint256 flipped = nonceBitMap[from][word] ^= bit;

        // check if the bit was already flipped.
        if (flipped & bit == 0) revert InvalidNonce();
    }
}
