// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { MessageHashUtils } from "./MessageHashUtils.sol";

contract PermitUtils {
    bytes32 internal immutable DOMAIN_SEPARATOR;

    constructor(bytes32 _domainSeparator) {
        DOMAIN_SEPARATOR = _domainSeparator;
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
