// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { BaseTest } from "../Base.t.sol";

import { ERC6909XUtils } from "../utils/ERC6909XUtils.sol";
import { ERC6909Test as ERC6909 } from "./ERC6909Test.sol";

contract ERC6909Test is BaseTest {
    error ExpiredSignature(uint256 deadline);
    error InvalidSigner();
    error InvalidPermitParams();

    ERC6909 public erc6909;
    ERC6909XUtils public permitUtils;

    function setUp() public override {
        super.setUp();

        erc6909 = new ERC6909("ERC6909", "V1");
        permitUtils = new ERC6909XUtils(erc6909.DOMAIN_SEPARATOR());
    }

    /* -------------------------------------------------------------------------- */
    /*                                  MINT_TEST                                 */
    /* -------------------------------------------------------------------------- */

    function testFuzz_mint(address _account, uint256 _id, uint256 _amount) public {
        vm.prank(_account);
        erc6909.mint(_id, _amount);

        assertEq(erc6909.balanceOf(_account, _id), _amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  BURN_TEST                                 */
    /* -------------------------------------------------------------------------- */

    function testFuzz_burn(address _account, uint256 _id, uint256 _amount) public {
        testFuzz_mint(_account, _id, _amount);

        vm.prank(_account);
        erc6909.burn(_id, _amount);

        assertEq(erc6909.balanceOf(_account, _id), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                TRANSFER_TEST                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_transfer(address _from, address _to, uint256 _id, uint256 _amount) public {
        vm.assume(_from != _to);
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        erc6909.transfer(_to, _id, _amount);

        assertEq(erc6909.balanceOf(_from, _id), 0);
        assertEq(erc6909.balanceOf(_to, _id), _amount);
    }

    function testFuzz_transfer_Revert_whenTransferAmountGreateThanBalance(
        address _from,
        address _to,
        uint256 _id,
        uint256 _amount
    )
        public
    {
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        vm.expectRevert();
        erc6909.transfer(_to, _id, _amount + 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                             TRANSFER_FROM_TEST                             */
    /* -------------------------------------------------------------------------- */

    function testFuzz_transferFrom(address _from, address _to, address _spender, uint256 _id, uint256 _amount) public {
        vm.assume(_amount > 0 && _spender != _from && _from != _to);

        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        erc6909.approve(_spender, _id, _amount);

        vm.prank(_spender);
        erc6909.transferFrom(_from, _to, _id, _amount);

        assertEq(erc6909.balanceOf(_from, _id), 0);
        assertEq(erc6909.balanceOf(_to, _id), _amount);
    }

    function testFuzz_transferFrom_Revert_whenTransferAmountGreateThanBalance(
        address _from,
        address _to,
        address _spender,
        uint256 _id,
        uint256 _amount
    )
        public
    {
        vm.assume(_amount > 0 && _spender != _from);
        vm.assume(_amount < type(uint256).max);
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        erc6909.approve(_spender, _id, _amount + 1);

        vm.prank(_spender);
        vm.expectRevert();
        erc6909.transferFrom(_from, _to, _id, _amount + 1);
    }

    function testFuzz_transferFrom_Revert_whenTransferAmountGreateThanAllowance(
        address _from,
        address _to,
        address _spender,
        uint256 _id,
        uint128 _amount
    )
        public
    {
        vm.assume(_amount > 0 && _spender != _from);
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        erc6909.approve(_spender, _id, uint256(_amount) - 1);

        vm.prank(_spender);
        vm.expectRevert();
        erc6909.transferFrom(_from, _to, _id, _amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                                APRROVE_TEST                                */
    /* -------------------------------------------------------------------------- */

    function testFuzz_approve(address _owner, address _spender, uint256 _id, uint256 _amount) public {
        vm.prank(_owner);
        erc6909.approve(_spender, _id, _amount);

        assertEq(erc6909.allowance(_owner, _spender, _id), _amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                                OPERATOR_TEST                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_setOperator(address _owner, address _operator, bool _approved) public {
        vm.prank(_owner);
        erc6909.setOperator(_operator, _approved);

        assertEq(erc6909.isOperator(_owner, _operator), _approved);
    }

    /* -------------------------------------------------------------------------- */
    /*                           OPERATOR_TRANSFER_TEST                           */
    /* -------------------------------------------------------------------------- */

    function testFuzz_operatorTransfer(address _from, address _to, uint256 _id, uint256 _amount) public {
        vm.assume(_from != _to);
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        erc6909.setOperator(address(this), true);

        erc6909.transferFrom(_from, _to, _id, _amount);

        assertEq(erc6909.balanceOf(_from, _id), 0);
        assertEq(erc6909.balanceOf(_to, _id), _amount);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 PERMIT_TEST                                */
    /* -------------------------------------------------------------------------- */

    function testFuzz_approveBySig(address _spender, uint256 _id, bool _isOperator, uint256 _value) public {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _value = 0;
        }

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, _isOperator, _id, _value, address(0), "", nonce++, deadline
        );

        erc6909.approveBySig(_owner.addr, _spender, _isOperator, _id, _value, deadline, signature);

        if (_isOperator) {
            assertEq(erc6909.isOperator(_owner.addr, _spender), true);
        } else {
            assertEq(erc6909.allowance(_owner.addr, _spender, _id), _value);
        }
    }

    function testFuzz_approveBySig_Revert_whenExpired(
        address _spender,
        uint256 _id,
        bool _isOperator,
        uint256 _value
    )
        public
    {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _value = 0;
        }

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = block.timestamp - 1;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, _isOperator, _id, _value, address(0), "", nonce++, deadline
        );

        vm.expectRevert(abi.encodeWithSelector(ExpiredSignature.selector, deadline));
        erc6909.approveBySig(_owner.addr, _spender, _isOperator, _id, _value, deadline, signature);
    }

    function testFuzz_approveBySig_Revert_whenDoubleSpend(address _spender, uint256 _id, uint256 _value) public {
        bool isOperator = false;

        Account memory _owner = ALICE;

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, isOperator, _id, _value, address(0), "", nonce++, deadline
        );

        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, deadline, signature);

        vm.expectRevert(InvalidSigner.selector);
        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, deadline, signature);
    }

    function testFuzz_approveBySig_Revert_wehnInvalidPermitParams(
        address _spender,
        uint256 _id,
        uint256 _value
    )
        public
    {
        vm.assume(_id != 0 || _value != 0);

        bool isOperator = true;

        Account memory _owner = ALICE;

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, isOperator, _id, _value, address(0), "", nonce++, deadline
        );

        vm.expectRevert(InvalidPermitParams.selector);
        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, deadline, signature);
    }

    function getPermitSignature(
        bool _temporary,
        address _owner,
        uint256 _key,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint256 _deadline
    )
        public
        view
        returns (bytes memory signature)
    {
        bytes32 digest =
            getDigest(_temporary, _owner, _spender, _isOperator, _id, _value, _target, _data, _nonce, _deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function getDigest(
        bool _temporary,
        address _owner,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint256 _deadline
    )
        public
        view
        returns (bytes32 digest)
    {
        ERC6909XUtils.ERC6909XApproveAndCall memory permit = ERC6909XUtils.ERC6909XApproveAndCall({
            temporary: _temporary,
            owner: _owner,
            spender: _spender,
            isOperator: _isOperator,
            id: _id,
            amount: _value,
            target: _target,
            data: _data,
            nonce: _nonce,
            deadline: _deadline
        });

        digest = permitUtils.getTypedDataHash(permit);
    }
}
