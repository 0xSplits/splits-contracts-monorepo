// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { IERC165 } from "../interfaces/IERC165.sol";
import { IERC6909 } from "../interfaces/IERC6909.sol";

/// @notice Minimalist and gas efficient standard ERC6909 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC6909.sol)
abstract contract ERC6909 is IERC6909 {
    /* -------------------------------------------------------------------------- */
    /*                               ERC6909 STORAGE                              */
    /* -------------------------------------------------------------------------- */

    mapping(address owner => mapping(address operator => bool approved)) public isOperator;

    mapping(address owner => mapping(uint256 id => uint256 amount)) public balanceOf;

    mapping(address owner => mapping(address spender => mapping(uint256 tokenId => uint256 amount))) public allowance;

    /* -------------------------------------------------------------------------- */
    /*                                ERC6909 LOGIC                               */
    /* -------------------------------------------------------------------------- */

    function transfer(address receiver, uint256 id, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender][id] -= amount;

        balanceOf[receiver][id] += amount;

        emit Transfer(msg.sender, msg.sender, receiver, id, amount);

        return true;
    }

    function transferFrom(address sender, address receiver, uint256 id, uint256 amount) public virtual returns (bool) {
        if (msg.sender != sender && !isOperator[sender][msg.sender]) {
            uint256 allowed = allowance[sender][msg.sender][id];
            if (allowed != type(uint256).max) allowance[sender][msg.sender][id] = allowed - amount;
        }

        balanceOf[sender][id] -= amount;

        balanceOf[receiver][id] += amount;

        emit Transfer(msg.sender, sender, receiver, id, amount);

        return true;
    }

    function approve(address spender, uint256 id, uint256 amount) public virtual returns (bool) {
        return _approve(msg.sender, spender, id, amount);
    }

    function setOperator(address operator, bool approved) public virtual returns (bool) {
        return _setOperator(msg.sender, operator, approved);
    }

    /* -------------------------------------------------------------------------- */
    /*                                ERC165 LOGIC                                */
    /* -------------------------------------------------------------------------- */

    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC6909).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /* -------------------------------------------------------------------------- */
    /*                          INTERNAL MINT/BURN LOGIC                          */
    /* -------------------------------------------------------------------------- */

    function _mint(address receiver, uint256 id, uint256 amount) internal virtual {
        balanceOf[receiver][id] += amount;

        emit Transfer(msg.sender, address(0), receiver, id, amount);
    }

    function _burn(address sender, uint256 id, uint256 amount) internal virtual {
        balanceOf[sender][id] -= amount;

        emit Transfer(msg.sender, sender, address(0), id, amount);
    }

    function _setOperator(address _owner, address _operator, bool _approved) internal virtual returns (bool) {
        isOperator[_owner][_operator] = _approved;

        emit OperatorSet(_owner, _operator, _approved);

        return true;
    }

    function _approve(address _owner, address _spender, uint256 _id, uint256 _amount) internal virtual returns (bool) {
        allowance[_owner][_spender][_id] = _amount;

        emit Approval(_owner, _spender, _id, _amount);

        return true;
    }
}
