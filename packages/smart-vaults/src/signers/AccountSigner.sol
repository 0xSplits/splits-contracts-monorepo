// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Signer } from "./Signer.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @notice A signer backed by an EOA or ERC-1271 smart account.
 */
type AccountSigner is address;

function decodeAccountSigner(Signer memory signer_) pure returns (AccountSigner) {
    return AccountSigner.wrap(address(uint160(uint256(signer_.x))));
}

using AccountSignerLib for AccountSigner global;

library AccountSignerLib {
    function isValidSignature(
        AccountSigner signer,
        bytes32 messageHash,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNow(AccountSigner.unwrap(signer), messageHash, signature);
    }
}
