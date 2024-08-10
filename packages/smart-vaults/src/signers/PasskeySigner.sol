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

function decodePasskeySigner(Signer memory signer_) pure returns (PasskeySigner memory) {
    return PasskeySigner(uint256(signer_.slot1), uint256(signer_.slot2));
}

using PasskeySignerLib for PasskeySigner global;

library PasskeySignerLib {
    function isValidSignature(
        PasskeySigner memory signer,
        bytes32 messageHash,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));

        return WebAuthn.verify({
            challenge: abi.encode(messageHash),
            requireUV: false,
            webAuthnAuth: auth,
            x: signer.x,
            y: signer.y
        });
    }
}
