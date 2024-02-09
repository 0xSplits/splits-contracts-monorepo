// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { IERC6909X } from "../interfaces/IERC6909X.sol";
import { IERC6909XCallback } from "../interfaces/IERC6909XCallback.sol";
import { UnorderedNonces } from "../utils/Nonces.sol";
import { ERC6909 } from "./ERC6909.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { SignatureChecker } from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/**
 * @author forked from https://github.com/frangio/erc6909-extensions
 * @dev Implementation of the ERC-6909 Permit extension allowing approvals to spenders and operators to be made via
 * signatures.
 */
contract ERC6909X is ERC6909, EIP712, UnorderedNonces, IERC6909X {
    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    bytes32 public constant APPROVE_AND_CALL_TYPE_HASH = keccak256(
        // solhint-disable-next-line max-line-length
        "ERC6909XApproveAndCall(bool temporary,address owner,address spender,bool operator,uint256 id,uint256 amount,address target,bytes data,uint256 nonce,uint48 deadline)"
    );

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error ExpiredSignature(uint48 deadline);
    error InvalidSigner();
    error InvalidPermitParams();
    error InvalidAck();

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Initializes the {EIP712} domain separator.
     *
     */
    constructor(string memory _name, string memory _version) EIP712(_name, _version) { }

    /* -------------------------------------------------------------------------- */
    /*                              PUBLIC FUNCTIONS                              */
    /* -------------------------------------------------------------------------- */

    function supportsInterface(bytes4 interfaceId) public view override returns (bool supported) {
        return super.supportsInterface(interfaceId) || interfaceId == type(IERC6909X).interfaceId;
    }

    function temporaryApproveAndCall(
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes memory data
    )
        external
        returns (bool)
    {
        _temporaryApproveAndCall(msg.sender, spender, operator, id, amount, target, data);
        return true;
    }

    function temporaryApproveAndCallBySig(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes memory data,
        uint256 nonce,
        uint48 deadline,
        bytes memory signature
    )
        external
        returns (bool)
    {
        // if the nonce is invalid, the function will revert.
        useNonce(owner, nonce);
        _validateApproveAndCallSignature( /* temporary = */
            true, owner, spender, operator, id, amount, target, data, nonce, deadline, signature
        );
        _temporaryApproveAndCall(owner, spender, operator, id, amount, target, data);
        return true;
    }

    function approveBySig(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint48 deadline,
        bytes memory signature
    )
        external
        returns (bool)
    {
        // if the nonce is invalid, the function will revert.
        useNonce(owner, nonce);
        _validateApproveAndCallSignature( /* temporary = */
            false, owner, spender, operator, id, amount, address(0), "", nonce, deadline, signature
        );
        _setSpenderAccess(owner, spender, operator, id, amount);
        return true;
    }

    function _temporaryApproveAndCall(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes memory data
    )
        internal
    {
        (bool prevIsOperator, uint256 prevAllowance) = _setSpenderAccess(owner, spender, operator, id, amount);

        bytes4 ack = IERC6909XCallback(target).onTemporaryApprove(owner, operator, id, amount, data);
        if (ack != IERC6909XCallback.onTemporaryApprove.selector) revert InvalidAck();

        if (operator) {
            isOperator[owner][spender] = prevIsOperator;
        } else {
            allowance[owner][spender][id] = prevAllowance;
        }
    }

    function _setSpenderAccess(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount
    )
        internal
        returns (bool prevIsOperator, uint256 prevAllowance)
    {
        if (operator) {
            if (id != 0 || amount != 0) revert InvalidPermitParams();
            prevIsOperator = isOperator[owner][spender];
            isOperator[owner][spender] = true;
        } else {
            prevAllowance = allowance[owner][spender][id];
            allowance[owner][spender][id] = amount;
        }
    }

    function _validateApproveAndCallSignature(
        bool temporary,
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes memory data,
        uint256 nonce,
        uint48 deadline,
        bytes memory signature
    )
        internal
        view
    {
        if (block.timestamp > deadline) revert ExpiredSignature(deadline);
        bytes32 messageHash =
            _hashApproveAndCallMessage(temporary, owner, spender, operator, id, amount, target, data, nonce, deadline);
        if (!SignatureChecker.isValidSignatureNow(owner, messageHash, signature)) revert InvalidSigner();
    }

    function _hashApproveAndCallMessage(
        bool temporary,
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes memory data,
        uint256 nonce,
        uint48 deadline
    )
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    APPROVE_AND_CALL_TYPE_HASH,
                    temporary,
                    owner,
                    spender,
                    operator,
                    id,
                    amount,
                    target,
                    keccak256(data),
                    nonce,
                    deadline
                )
            )
        );
    }

    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }
}
