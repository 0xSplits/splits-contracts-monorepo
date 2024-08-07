// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * A signer backed by an EOA or ERC-1271 smart account.
 */
type AccountSigner is address;

function decodeAccountSigner(bytes memory signer) pure returns (AccountSigner) {
    return AccountSigner.wrap(abi.decode(signer, (address)));
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
