// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC6909X } from "../interfaces/IERC6909X.sol";
import { IERC6909XCallback } from "../interfaces/IERC6909XCallback.sol";
import { UnorderedNonces } from "../utils/UnorderedNonces.sol";
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

    /// @notice The EIP-712 typehash for approveAndCall
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

    /**
     * @notice Returns true if `interfaceId` is supported.
     * @dev Supports ERC6909X, ERC165, and ERC6909.
     * @param _interfaceId The interface identifier, as specified in ERC-165.
     */
    function supportsInterface(bytes4 _interfaceId) public view override returns (bool supported) {
        return super.supportsInterface({ _interfaceId: _interfaceId }) || _interfaceId == type(IERC6909X).interfaceId;
    }

    /**
     * @notice Temporary grants spender allowance or operator status and forwards the data to the target contract.
     * @dev The function will revert if the target contract does not return the expected ack.
     * @param _spender The address of the account that will be allowed to spend the tokens.
     * @param _operator True if the spender is to be set as an operator. if True, id and amount should be 0.
     * @param _id The ID of the token to be spent.
     * @param _amount The amount of the token to be spent.
     * @param _target The address of the contract to be called.
     * @param _data The data to be sent to the target contract.
     * @return True Returns true if the call is successful.
     */
    function temporaryApproveAndCall(
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        address _target,
        bytes memory _data
    )
        external
        returns (bool)
    {
        _temporaryApproveAndCall({
            _owner: msg.sender,
            _spender: _spender,
            _operator: _operator,
            _id: _id,
            _amount: _amount,
            _target: _target,
            _data: _data
        });
        return true;
    }

    /**
     * @notice Temporary grants spender allowance or operator status and forwards the data to the target contract using
     * a signature.
     * @dev The function will revert if the signature is invalid or the target contract does not return the expected
     * ack.
     * @param _owner The address of the account that will be allowing the spender to spend the tokens.
     * @param _spender The address of the account that will be allowed to spend the tokens.
     * @param _operator True if the spender is to be set as an operator. if True, id and amount should be 0.
     * @param _id The ID of the token to be spent.
     * @param _amount The amount of the token to be spent.
     * @param _target The address of the contract to be called.
     * @param _data The data to be sent to the target contract.
     * @param _nonce Unused nonce.
     * @param _deadline The deadline timestamp for the signature.
     * @param _signature The signature to be validated.
     * @return True Returns true if the call is successful.
     */
    function temporaryApproveAndCallBySig(
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint48 _deadline,
        bytes memory _signature
    )
        external
        returns (bool)
    {
        // if the nonce is invalid, the function will revert.
        useNonce({ _from: _owner, _nonce: _nonce });

        _validateApproveAndCallSignature({
            _temporary: true,
            _owner: _owner,
            _spender: _spender,
            _operator: _operator,
            _id: _id,
            _amount: _amount,
            _target: _target,
            _data: _data,
            _nonce: _nonce,
            _deadline: _deadline,
            _signature: _signature
        });

        _temporaryApproveAndCall({
            _owner: _owner,
            _spender: _spender,
            _operator: _operator,
            _id: _id,
            _amount: _amount,
            _target: _target,
            _data: _data
        });

        return true;
    }

    /**
     * @notice Grants spender allowance or operator status using a signature.
     * @dev The function will revert if the signature is invalid.
     * @param _owner The address of the account that will be allowing the spender to spend the tokens.
     * @param _spender The address of the account that will be allowed to spend the tokens.
     * @param _operator True if the spender is to be set as an operator. if True, id and amount should be 0.
     * @param _id The ID of the token to be spent.
     * @param _amount The amount of the token to be spent.
     * @param _nonce Unused nonce.
     * @param _deadline The deadline timestamp for the signature.
     * @param _signature The signature to be validated.
     * @return True returns true if the call is successful.
     */
    function approveBySig(
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce,
        uint48 _deadline,
        bytes memory _signature
    )
        external
        returns (bool)
    {
        // if the nonce is invalid, the function will revert.
        useNonce({ _from: _owner, _nonce: _nonce });

        _validateApproveAndCallSignature({
            _temporary: false,
            _owner: _owner,
            _spender: _spender,
            _operator: _operator,
            _id: _id,
            _amount: _amount,
            _target: address(0),
            _data: "",
            _nonce: _nonce,
            _deadline: _deadline,
            _signature: _signature
        });

        _setSpenderAccess({ _owner: _owner, _spender: _spender, _operator: _operator, _id: _id, _amount: _amount });

        return true;
    }

    /* -------------------------------------------------------------------------- */
    /*                             INTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    function _temporaryApproveAndCall(
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        address _target,
        bytes memory _data
    )
        internal
    {
        (bool prevIsOperator, uint256 prevAllowance) =
            _setSpenderAccess({ _owner: _owner, _spender: _spender, _operator: _operator, _id: _id, _amount: _amount });

        bytes4 ack = IERC6909XCallback(_target).onTemporaryApprove({
            owner: _owner,
            operator: _operator,
            id: _id,
            amount: _amount,
            data: _data
        });
        if (ack != IERC6909XCallback.onTemporaryApprove.selector) revert InvalidAck();

        if (_operator) {
            _setOperator({ _owner: _owner, _operator: _spender, _approved: prevIsOperator });
        } else {
            _approve({ _owner: _owner, _spender: _spender, _id: _id, _amount: prevAllowance });
        }
    }

    function _setSpenderAccess(
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount
    )
        internal
        returns (bool prevIsOperator, uint256 prevAllowance)
    {
        if (_operator) {
            if (_id != 0 || _amount != 0) revert InvalidPermitParams();
            prevIsOperator = isOperator[_owner][_spender];

            _setOperator({ _owner: _owner, _operator: _spender, _approved: true });
        } else {
            prevAllowance = allowance[_owner][_spender][_id];

            _approve({ _owner: _owner, _spender: _spender, _id: _id, _amount: _amount });
        }
    }

    function _validateApproveAndCallSignature(
        bool _temporary,
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint48 _deadline,
        bytes memory _signature
    )
        internal
        view
    {
        if (block.timestamp > _deadline) revert ExpiredSignature(_deadline);

        bytes32 messageHash = _hashApproveAndCallMessage({
            _temporary: _temporary,
            _owner: _owner,
            _spender: _spender,
            _operator: _operator,
            _id: _id,
            _amount: _amount,
            _target: _target,
            _data: _data,
            _nonce: _nonce,
            _deadline: _deadline
        });

        if (!SignatureChecker.isValidSignatureNow({ signer: _owner, hash: messageHash, signature: _signature })) {
            revert InvalidSigner();
        }
    }

    function _hashApproveAndCallMessage(
        bool _temporary,
        address _owner,
        address _spender,
        bool _operator,
        uint256 _id,
        uint256 _amount,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint48 _deadline
    )
        internal
        view
        returns (bytes32)
    {
        return _hashTypedDataV4({
            structHash: keccak256(
                abi.encode(
                    APPROVE_AND_CALL_TYPE_HASH,
                    _temporary,
                    _owner,
                    _spender,
                    _operator,
                    _id,
                    _amount,
                    _target,
                    keccak256(_data),
                    _nonce,
                    _deadline
                )
            )
        });
    }

    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }
}
