// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/**
 * @notice An EOA or Passkey signer.
 *
 * @dev For a Signer to be valid it has to be either an EOA or a Passkey signer.
 *      - EOA -> y has to be empty and x has to be a valid address.
 *      - Passkey -> both x and y have to be non empty.
 */
struct Signer {
    bytes32 x;
    bytes32 y;
}

function decodeSigner(bytes calldata signer_) pure returns (Signer memory) {
    return abi.decode(signer_, (Signer));
}

function encodeSigner(address signer_) pure returns (Signer memory) {
    return Signer(bytes32(uint256(uint160(signer_))), bytes32(0));
}

function encodeSigner(uint256 x_, uint256 y_) pure returns (Signer memory) {
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
        return signer_.y == ZERO && uint256(bytes32(signer_.x)) <= type(uint160).max;
    }

    function isPasskey(Signer calldata signer_) internal pure returns (bool) {
        return signer_.x != ZERO && signer_.y != ZERO;
    }

    // not sure if I like this, any suggestions?
    function isPasskeyMem(Signer memory signer_) internal pure returns (bool) {
        return signer_.x != ZERO && signer_.y != ZERO;
    }

    function isValid(Signer calldata signer_) internal pure returns (bool) {
        return isEOA(signer_) || isPasskey(signer_);
    }

    function isEmptyMem(Signer memory signer_) internal pure returns (bool) {
        return signer_.x == ZERO && signer_.y == ZERO;
    }
}
