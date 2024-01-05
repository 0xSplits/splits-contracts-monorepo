// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract PermitUtils {
    bytes32 internal DOMAIN_SEPARATOR;

    constructor(bytes32 _domain_separator) {
        DOMAIN_SEPARATOR = _domain_separator;
    }

    bytes32 private constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,bool isOperator,uint256 id,uint256 value,uint256 nonce,uint256 deadline)"
    );

    struct Permit {
        address owner;
        address spender;
        bool isOperator;
        uint256 id;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    // computes the hash of a permit
    function getStructHash(Permit memory _permit) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                _permit.owner,
                _permit.spender,
                _permit.isOperator,
                _permit.id,
                _permit.value,
                _permit.nonce,
                _permit.deadline
            )
        );
    }

    function getTypedDataHash(Permit memory _permit) public view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, getStructHash((_permit)));
    }
}
