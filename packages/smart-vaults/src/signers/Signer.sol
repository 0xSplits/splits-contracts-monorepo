// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/**
 * @notice An EOA or Passkey signer.
 *
 * @dev For a Signer to be valid it has to be either an EOA or a Passkey signer.
 *      - EOA -> slot2 has to be empty and slot1 has to be a valid address.
 *      - Passkey -> both slot1 and slot2 have to be non empty.
 */
struct Signer {
    bytes32 slot1;
    bytes32 slot2;
}

function createSigner(address signer_) pure returns (Signer memory) {
    return Signer(bytes32(uint256(uint160(signer_))), bytes32(0));
}

function createSigner(uint256 x_, uint256 y_) pure returns (Signer memory) {
    return Signer(bytes32(x_), bytes32(y_));
}

using SignerLib for Signer global;

library SignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    bytes32 constant ZERO = bytes32(0);

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function isEOA(Signer calldata signer_) internal pure returns (bool) {
        uint256 slot1 = uint256(bytes32(signer_.slot1));
        return signer_.slot2 == ZERO && slot1 <= type(uint160).max && slot1 > 0;
    }

    function isPasskey(Signer calldata signer_) internal pure returns (bool) {
        return signer_.slot1 != ZERO && signer_.slot2 != ZERO;
    }

    function isPasskeyMem(Signer memory signer_) internal pure returns (bool) {
        return signer_.slot1 != ZERO && signer_.slot2 != ZERO;
    }

    function isValid(Signer calldata signer_) internal pure returns (bool) {
        return isEOA(signer_) || isPasskey(signer_);
    }

    function isEmpty(Signer calldata signer_) internal pure returns (bool) {
        return signer_.slot1 == ZERO && signer_.slot2 == ZERO;
    }

    function isEmptyMem(Signer memory signer_) internal pure returns (bool) {
        return signer_.slot1 == ZERO && signer_.slot2 == ZERO;
    }
}
