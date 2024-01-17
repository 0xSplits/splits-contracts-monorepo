// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { BaseTest } from "../Base.t.sol";

import { PermitUtils } from "../utils/PermitUtils.sol";
import { ERC6909Test as ERC6909 } from "./ERC6909Test.sol";

contract ERC6909Test is BaseTest {
    error ERC2612ExpiredSignature(uint256 deadline);
    error ERC2612InvalidSigner(address signer, address owner);
    error InvalidPermitParams();

    ERC6909 public erc6909;
    PermitUtils public permitUtils;

    function setUp() public override {
        super.setUp();

        erc6909 = new ERC6909("ERC6909", "V1");
        permitUtils = new PermitUtils(erc6909.DOMAIN_SEPARATOR());
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

    function testFuzz_permit(address _spender, uint256 _id, bool _isOperator, uint256 _value) public {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _value = 0;
        }

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        (uint8 v, bytes32 r, bytes32 s) =
            getPermitSignature(_owner.addr, _owner.key, _spender, _isOperator, _id, _value, nonce++, deadline);

        erc6909.permit(_owner.addr, _spender, _isOperator, _id, _value, deadline, v, r, s);

        if (_isOperator) {
            assertEq(erc6909.isOperator(_owner.addr, _spender), true);
        } else {
            assertEq(erc6909.allowance(_owner.addr, _spender, _id), _value);
        }
    }

    function testFuzz_permit_Revert_whenExpired(
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

        (uint8 v, bytes32 r, bytes32 s) =
            getPermitSignature(_owner.addr, _owner.key, _spender, _isOperator, _id, _value, nonce++, deadline);

        vm.expectRevert(abi.encodeWithSelector(ERC2612ExpiredSignature.selector, deadline));
        erc6909.permit(_owner.addr, _spender, _isOperator, _id, _value, deadline, v, r, s);
    }

    function testFuzz_permit_Revert_whenDoubleSpend(address _spender, uint256 _id, uint256 _value) public {
        bool isOperator = false;

        Account memory _owner = ALICE;

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        (uint8 v, bytes32 r, bytes32 s) =
            getPermitSignature(_owner.addr, _owner.key, _spender, isOperator, _id, _value, nonce++, deadline);

        erc6909.permit(_owner.addr, _spender, isOperator, _id, _value, deadline, v, r, s);

        vm.expectRevert();
        erc6909.permit(_owner.addr, _spender, isOperator, _id, _value, deadline, v, r, s);
    }

    function testFuzz_permit_Revert_wehnInvalidPermitParams(address _spender, uint256 _id, uint256 _value) public {
        vm.assume(_id != 0 || _value != 0);

        bool isOperator = true;

        Account memory _owner = ALICE;

        uint256 nonce = erc6909.nonces(_owner.addr);

        uint256 deadline = type(uint256).max;

        (uint8 v, bytes32 r, bytes32 s) =
            getPermitSignature(_owner.addr, _owner.key, _spender, isOperator, _id, _value, nonce++, deadline);

        vm.expectRevert(InvalidPermitParams.selector);
        erc6909.permit(_owner.addr, _spender, isOperator, _id, _value, deadline, v, r, s);
    }

    function getPermitSignature(
        address _owner,
        uint256 _key,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        uint256 _nonce,
        uint256 _deadline
    )
        public
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        PermitUtils.Permit memory permit = PermitUtils.Permit({
            owner: _owner,
            spender: _spender,
            isOperator: _isOperator,
            id: _id,
            value: _value,
            nonce: _nonce,
            deadline: _deadline
        });

        bytes32 digest = permitUtils.getTypedDataHash(permit);

        (v, r, s) = vm.sign(_key, digest);
    }
}
