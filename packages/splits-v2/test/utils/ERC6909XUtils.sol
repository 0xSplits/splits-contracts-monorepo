// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { MessageHashUtils } from "./MessageHashUtils.sol";

contract ERC6909XUtils {
    bytes32 internal immutable DOMAIN_SEPARATOR;

    constructor(bytes32 _domainSeparator) {
        DOMAIN_SEPARATOR = _domainSeparator;
    }

    bytes32 public constant APPROVE_AND_CALL_TYPE_HASH = keccak256(
        // solhint-disable-next-line max-line-length
        "ERC6909XApproveAndCall(bool temporary,address owner,address spender,bool operator,uint256 id,uint256 amount,address target,bytes data,uint256 nonce,uint256 deadline)"
    );

    struct ERC6909XApproveAndCall {
        bool temporary;
        address owner;
        address spender;
        bool isOperator;
        uint256 id;
        uint256 amount;
        address target;
        bytes data;
        uint256 nonce;
        uint256 deadline;
    }

    // computes the hash of a permit
    function getStructHash(ERC6909XApproveAndCall memory _permit) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                APPROVE_AND_CALL_TYPE_HASH,
                _permit.temporary,
                _permit.owner,
                _permit.spender,
                _permit.isOperator,
                _permit.id,
                _permit.amount,
                _permit.target,
                keccak256(_permit.data),
                _permit.nonce,
                _permit.deadline
            )
        );
    }

    function getTypedDataHash(ERC6909XApproveAndCall memory _permit) public view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, getStructHash((_permit)));
    }
}
