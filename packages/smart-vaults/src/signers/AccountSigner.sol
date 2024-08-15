// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Signer } from "./Signer.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";

/**
 * @notice A signer backed by an EOA or ERC-1271 smart account.
 */
type AccountSigner is address;

/// @notice converts Signer to AccountSigner.
function decodeAccountSigner(Signer memory signer_) pure returns (AccountSigner) {
    return AccountSigner.wrap(address(uint160(uint256(signer_.slot1))));
}

using AccountSignerLib for AccountSigner global;

/**
 * @notice Library for verifying AccountSigner signatures.
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 */
library AccountSignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Verifies if the `signer` has signed the provided `messageHash`.
     *
     * @param signer_ Account signer.
     * @param messageHash_ Message hash that should be signed by the signer.
     * @param signature_ abi.encode(r,s,v) signature.
     * @return isValid true when signer has signed the messageHash otherwise false.
     */
    function isValidSignature(
        AccountSigner signer_,
        bytes32 messageHash_,
        bytes memory signature_
    )
        internal
        view
        returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNow(AccountSigner.unwrap(signer_), messageHash_, signature_);
    }
}
