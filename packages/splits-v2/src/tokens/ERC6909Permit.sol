// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { ERC6909 } from "./ERC6909.sol";

/**
 * @dev Implementation of the ERC-6909 Permit extension allowing approvals to spenders and operators to be made via
 * signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[ERC-2612].
 */
contract ERC6909Permit is ERC6909, EIP712, Nonces {
    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,bool isOperator,uint256 id,uint256 value,uint256 nonce,uint256 deadline)"
    );

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error ERC2612ExpiredSignature(uint256 deadline);
    error ERC2612InvalidSigner(address signer, address owner);
    error InvalidPermitParams();

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     */
    constructor(string memory name) EIP712(name, "1") { }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Permit based approval to a spender or operator.
     * @param owner The owner of the token.
     * @param spender The spender of the token.
     * @param isOperator Whether the spender is an operator or not.
     * @param id The id of the token.
     * @param value The amount of the token.
     * @param deadline The deadline timestamp, type(uint256).max for max deadline.
     * @param v The recovery byte of the signature.
     * @param r Half of the ECDSA signature pair.
     * @param s Half of the ECDSA signature pair.
     * @dev if isOperator is true, id and value should be set to zero.
     */
    function permit(
        address owner,
        address spender,
        bool isOperator,
        uint256 id,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        virtual
    {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }

        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, v, r, s);
        if (signer != owner) {
            revert ERC2612InvalidSigner(signer, owner);
        }

        if (isOperator) {
            if (id != 0 || value != 0) {
                revert InvalidPermitParams();
            }
            setOperator(spender, isOperator);
        } else {
            allowance[owner][spender][id] = value;

            emit Approval(owner, spender, id, value);
        }
    }

    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }
}
