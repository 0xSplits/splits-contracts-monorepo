// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC165 } from "../interfaces/IERC165.sol";
import { IERC6909 } from "../interfaces/IERC6909.sol";

/// @notice Minimalist and gas efficient standard ERC6909 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC6909.sol)
abstract contract ERC6909 is IERC6909 {
    /* -------------------------------------------------------------------------- */
    /*                               ERC6909 STORAGE                              */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IERC6909
    mapping(address owner => mapping(address operator => bool approved)) public isOperator;

    /// @inheritdoc IERC6909
    mapping(address owner => mapping(uint256 id => uint256 amount)) public balanceOf;

    /// @inheritdoc IERC6909
    mapping(address owner => mapping(address spender => mapping(uint256 tokenId => uint256 amount))) public allowance;

    /* -------------------------------------------------------------------------- */
    /*                                ERC6909 LOGIC                               */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IERC6909
    function transfer(address _receiver, uint256 _id, uint256 _amount) public virtual returns (bool) {
        balanceOf[msg.sender][_id] -= _amount;

        balanceOf[_receiver][_id] += _amount;

        emit Transfer({ caller: msg.sender, sender: msg.sender, receiver: _receiver, id: _id, amount: _amount });

        return true;
    }

    /// @inheritdoc IERC6909
    function transferFrom(
        address _sender,
        address _receiver,
        uint256 _id,
        uint256 _amount
    )
        public
        virtual
        returns (bool)
    {
        if (msg.sender != _sender && !isOperator[_sender][msg.sender]) {
            uint256 allowed = allowance[_sender][msg.sender][_id];
            if (allowed != type(uint256).max) allowance[_sender][msg.sender][_id] = allowed - _amount;
        }

        balanceOf[_sender][_id] -= _amount;

        balanceOf[_receiver][_id] += _amount;

        emit Transfer({ caller: msg.sender, sender: _sender, receiver: _receiver, id: _id, amount: _amount });

        return true;
    }

    /// @inheritdoc IERC6909
    function approve(address _spender, uint256 _id, uint256 _amount) public virtual returns (bool) {
        return _approve({ _owner: msg.sender, _spender: _spender, _id: _id, _amount: _amount });
    }

    /// @inheritdoc IERC6909
    function setOperator(address _operator, bool _approved) public virtual returns (bool) {
        return _setOperator({ _owner: msg.sender, _operator: _operator, _approved: _approved });
    }

    /* -------------------------------------------------------------------------- */
    /*                                ERC165 LOGIC                                */
    /* -------------------------------------------------------------------------- */

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 _interfaceId) public view virtual returns (bool) {
        return _interfaceId == type(IERC6909).interfaceId || _interfaceId == type(IERC165).interfaceId;
    }

    /* -------------------------------------------------------------------------- */
    /*                          INTERNAL MINT/BURN LOGIC                          */
    /* -------------------------------------------------------------------------- */

    function _mint(address _receiver, uint256 _id, uint256 _amount) internal virtual {
        balanceOf[_receiver][_id] += _amount;

        emit Transfer({ caller: msg.sender, sender: address(0), receiver: _receiver, id: _id, amount: _amount });
    }

    function _burn(address _sender, uint256 _id, uint256 _amount) internal virtual {
        balanceOf[_sender][_id] -= _amount;

        emit Transfer({ caller: msg.sender, sender: _sender, receiver: address(0), id: _id, amount: _amount });
    }

    function _setOperator(address _owner, address _operator, bool _approved) internal virtual returns (bool) {
        isOperator[_owner][_operator] = _approved;

        emit OperatorSet({ owner: _owner, spender: _operator, approved: _approved });

        return true;
    }

    function _approve(address _owner, address _spender, uint256 _id, uint256 _amount) internal virtual returns (bool) {
        allowance[_owner][_spender][_id] = _amount;

        emit Approval({ owner: _owner, spender: _spender, id: _id, amount: _amount });

        return true;
    }
}
