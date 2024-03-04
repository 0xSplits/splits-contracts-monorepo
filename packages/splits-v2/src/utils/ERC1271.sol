// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @notice ERC-1271 with guards for same signer being used on multiple splits
 * @author Splits
 * Based on coinbase (https://github.com/coinbase/smart-wallet/blob/main/src/ERC1271.sol)
 */
abstract contract ERC1271 is EIP712 {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */
    /**
     * @dev We use `bytes32 hash` rather than `bytes message`
     * In the EIP-712 context, `bytes message` would be useful for showing users a full message
     * they are signing in some wallet preview. But in this case, to prevent replay
     * across accounts, we are always dealing with nested messages, and so the
     * input should be a EIP-191 or EIP-712 output hash.
     * E.g. The input hash would be result of
     *
     *  keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
     *
     *  OR
     *
     * keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage),
     */
    bytes32 private constant _MESSAGE_TYPEHASH = keccak256("SplitWalletMessage(bytes32 hash)");

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Initializes the {EIP712} domain separator.
     */
    constructor(string memory _name, string memory _version) EIP712(_name, _version) { }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Validates the signature with ERC1271 return, so that this account can also be used as a signer.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (
            SignatureChecker.isValidSignatureNow({
                signer: getSigner(),
                hash: replaySafeHash(hash),
                signature: signature
            })
        ) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /**
     * @dev Returns an EIP-712-compliant hash of `hash`,
     * where the domainSeparator includes address(this) and block.chainId
     * to protect against the same signature being used for many accounts.
     * @return
     *  keccak256(\x19\x01 || this.domainSeparator ||
     *      hashStruct(SplitWalletMessage({
     *          hash: `hash`
     *      }))
     *  )
     */
    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(_MESSAGE_TYPEHASH, hash)));
    }

    /// @dev returns the ERC1271 signer.
    function getSigner() internal view virtual returns (address);
}
