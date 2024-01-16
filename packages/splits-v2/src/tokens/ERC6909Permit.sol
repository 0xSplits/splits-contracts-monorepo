// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { Nonces } from "../utils/Nonces.sol";
import { ERC6909 } from "./ERC6909.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

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
     * @param _owner The owner of the token.
     * @param _spender The spender of the token.
     * @param _isOperator Whether the spender is an operator or not.
     * @param _id The id of the token.
     * @param _value The amount of the token.
     * @param _deadline The deadline timestamp, type(uint256).max for max deadline.
     * @param _v The recovery byte of the signature.
     * @param _r Half of the ECDSA signature pair.
     * @param _s Half of the ECDSA signature pair.
     * @dev if isOperator is true, id and value should be set to zero.
     */
    function permit(
        address _owner,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        uint256 _deadline,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    )
        public
        virtual
    {
        if (block.timestamp > _deadline) {
            revert ERC2612ExpiredSignature(_deadline);
        }

        uint256 nonce = _useNonce(_owner);

        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, _owner, _spender, _isOperator, _id, _value, nonce, _deadline));

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, _v, _r, _s);
        if (signer != _owner) {
            revert ERC2612InvalidSigner(signer, _owner);
        }

        if (_isOperator) {
            if (_id != 0 || _value != 0) {
                revert InvalidPermitParams();
            }
            _setOperator(_owner, _spender, _isOperator);
        } else {
            _approve(_owner, _spender, _id, _value);
        }
    }

    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }
}
