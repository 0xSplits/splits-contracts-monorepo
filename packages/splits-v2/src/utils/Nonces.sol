// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/**
 * @title Track hash Nonces
 * @dev Inspired by OpenZeppelin's Nonces.sol
 */
abstract contract Nonces {
    mapping(bytes32 hash => uint256) private _nonces;

    /**
     * @dev Returns the next unused nonce for a hash.
     */
    function nonces(bytes32 _hash) public view virtual returns (uint256) {
        return _nonces[_hash];
    }

    /**
     * @dev Consumes a nonce.
     *
     * Returns the current value and increments nonce.
     */
    function useNonce(bytes32 _hash) internal virtual returns (uint256) {
        // For each hash, the nonce has an initial value of 0, can only be incremented by one, and cannot be
        // decremented or reset. This guarantees that the nonce never overflows.
        unchecked {
            // It is important to do x++ and not ++x here.
            return _nonces[_hash]++;
        }
    }
}
