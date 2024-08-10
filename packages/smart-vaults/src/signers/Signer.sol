// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { WebAuthn } from "@web-authn/WebAuthn.sol";

/**
 * @notice An EOA or Passkey signer.
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

function encodeSigner(uint256 x, uint256 y) pure returns (Signer memory) {
    return Signer(bytes32(x), bytes32(y));
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

    function isEOA(Signer memory signer_) internal pure returns (bool) {
        return signer_.y == ZERO && uint256(bytes32(signer_.x)) <= type(uint160).max;
    }

    function isPasskey(Signer memory signer_) internal pure returns (bool) {
        return signer_.x != ZERO && signer_.y != ZERO;
    }

    function isValid(Signer memory signer_) internal pure returns (bool) {
        return isEOA(signer_) || isPasskey(signer_);
    }

    function isEmpty(Signer memory signer_) internal pure returns (bool) {
        return signer_.x == ZERO && signer_.y == ZERO;
    }
}
