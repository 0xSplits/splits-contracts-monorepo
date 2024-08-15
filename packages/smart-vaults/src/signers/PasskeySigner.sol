// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Signer } from "./Signer.sol";
import { WebAuthn } from "@web-authn/WebAuthn.sol";

/**
 * @notice A signer backed by a passkey.
 */
struct PasskeySigner {
    uint256 x;
    uint256 y;
}

/// @notice converts Signer to PasskeySigner.
function decodePasskeySigner(Signer memory signer_) pure returns (PasskeySigner memory) {
    return PasskeySigner(uint256(signer_.slot1), uint256(signer_.slot2));
}

using PasskeySignerLib for PasskeySigner global;

/**
 * @notice Library for verifying PasskeySigner signatures.
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 */
library PasskeySignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Verifies if the `signer` has signed the provided `messageHash`.
     *
     * @param signer_ Passkey signer.
     * @param messageHash_ Message hash that should be signed by the signer.
     * @param signature_ abi.encode(WebAuthn.WebAuthnAuth) signature.
     * @return isValid true when signer has signed the messageHash otherwise false.
     */
    function isValidSignature(
        PasskeySigner memory signer_,
        bytes32 messageHash_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature_, (WebAuthn.WebAuthnAuth));

        return WebAuthn.verify({
            challenge: abi.encode(messageHash_),
            requireUV: false,
            webAuthnAuth: auth,
            x: signer_.x,
            y: signer_.y
        });
    }
}
