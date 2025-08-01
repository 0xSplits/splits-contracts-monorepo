// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { BaseTest } from "../Base.t.sol";

import { IERC165 } from "../../src/interfaces/IERC165.sol";
import { IERC6909 } from "../../src/interfaces/IERC6909.sol";
import { IERC6909X } from "../../src/interfaces/IERC6909X.sol";

import { ERC6909XUtils } from "../utils/ERC6909XUtils.sol";

import { ERC6909Callback } from "./ERC6909Callback.sol";
import { ERC6909Test as ERC6909 } from "./ERC6909Test.sol";

contract ERC6909Test is BaseTest {
    error ExpiredSignature(uint48 deadline);
    error InvalidSigner();
    error InvalidPermitParams();
    error InvalidAck();
    error InvalidNonce();

    ERC6909 public erc6909;
    ERC6909Callback public callback;

    function setUp() public override {
        super.setUp();

        erc6909 = new ERC6909("ERC6909", "V1");
        permitUtils = new ERC6909XUtils(erc6909.DOMAIN_SEPARATOR());
        callback = new ERC6909Callback();
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

    function testFuzz_transfer(
        address _from,
        address _to,
        address _third,
        uint256 _id,
        uint256 _amount,
        uint256 _thirdAmount
    )
        public
    {
        vm.assume(_from != _third && _to != _third);
        testFuzz_mint(_from, _id, _amount);
        testFuzz_mint(_third, _id, _thirdAmount);

        vm.prank(_from);
        erc6909.transfer(_to, _id, _amount);

        if (_from != _to) {
            assertEq(erc6909.balanceOf(_from, _id), 0);
        }
        assertEq(erc6909.balanceOf(_to, _id), _amount);

        // assert that the third account balance is unchanged
        assertEq(erc6909.balanceOf(_third, _id), _thirdAmount);
    }

    function testFuzz_transfer_Revert_whenTransferAmountGreateThanBalance(
        address _from,
        address _to,
        uint256 _id,
        uint128 _amount
    )
        public
    {
        testFuzz_mint(_from, _id, _amount);

        vm.prank(_from);
        vm.expectRevert();
        erc6909.transfer(_to, _id, uint256(_amount) + 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                             TRANSFER_FROM_TEST                             */
    /* -------------------------------------------------------------------------- */

    function testFuzz_transferFrom(
        address _from,
        address _to,
        address _third,
        address _spender,
        uint256 _id,
        uint256 _amount,
        uint256 _thirdAmount
    )
        public
    {
        vm.assume(_amount > 0 && _spender != _from);
        vm.assume(_from != _third && _to != _third);

        testFuzz_mint(_from, _id, _amount);
        testFuzz_mint(_third, _id, _thirdAmount);

        vm.prank(_from);
        erc6909.approve(_spender, _id, _amount);

        vm.prank(_spender);
        erc6909.transferFrom(_from, _to, _id, _amount);

        if (_from != _to) {
            assertEq(erc6909.balanceOf(_from, _id), 0);
        }
        if (_amount != type(uint256).max) {
            assertEq(erc6909.allowance(_from, _spender, _id), 0);
        }
        assertEq(erc6909.balanceOf(_to, _id), _amount);
        // assert that the third account balance is unchanged
        assertEq(erc6909.balanceOf(_third, _id), _thirdAmount);
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
    /*                               ERC6909X TESTS                               */
    /* -------------------------------------------------------------------------- */

    function test_supportsInterface_ERC6909() public {
        bool supported = erc6909.supportsInterface(0x0f632fb3);
        assertEq(supported, true);
    }

    function test_supportsInterface_ERC165() public {
        bool supported = erc6909.supportsInterface(0x01ffc9a7);
        assertEq(supported, true);
    }

    function test_supportsInterface_IERC6909X() public {
        bool supported = erc6909.supportsInterface(0x4a31d207);
        assertEq(supported, true);
    }

    function testFuzz_temporaryApproveAndCall(address _owner, bool _isOperator, uint256 _id, uint256 _amount) public {
        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }
        address target = address(callback);
        bytes memory data;
        vm.prank(_owner);
        erc6909.temporaryApproveAndCall(target, _isOperator, _id, _amount, target, data);

        assertEq(erc6909.isOperator(_owner, target), false);
        assertEq(erc6909.allowance(_owner, target, _id), 0);
    }

    function test_temporaryApproveAndCall_Revert_InvalidAck() public {
        address target = address(this);
        bytes memory data;
        vm.prank(ALICE.addr);
        vm.expectRevert(InvalidAck.selector);
        erc6909.temporaryApproveAndCall(target, true, 0, 0, target, data);
    }

    function test_temporaryApproveAndCall_Revert_InvalidPermitParams() public {
        address target = address(callback);
        bytes memory data;
        vm.prank(ALICE.addr);
        vm.expectRevert(InvalidPermitParams.selector);
        erc6909.temporaryApproveAndCall(target, true, 1, 100, target, data);
    }

    function testFuzz_temporaryApproveAndCallBySig(
        bool _isOperator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce,
        uint256 _initialApproval
    )
        public
    {
        Account memory _owner = ALICE;

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), true);

        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }

        address target = address(callback);

        {
            vm.startPrank(_owner.addr);
            erc6909.approve(address(target), _id, _initialApproval);
            vm.stopPrank();
        }

        {
            bytes memory signature = getPermitSignature(
                true, _owner.addr, _owner.key, target, _isOperator, _id, _amount, target, "", _nonce, type(uint48).max
            );

            erc6909.temporaryApproveAndCallBySig(
                _owner.addr, target, _isOperator, _id, _amount, target, "", _nonce, type(uint48).max, signature
            );
        }

        assertEq(erc6909.isOperator(_owner.addr, target), false);
        assertEq(erc6909.allowance(_owner.addr, target, _id), _initialApproval);
        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), false);
    }

    function testFuzz_temporaryApproveAndCallBySig_Revert_whenExpired(
        bool _isOperator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }

        address target = address(callback);

        uint48 deadline = uint48(block.timestamp) - 1;

        bytes memory signature = getPermitSignature(
            true, _owner.addr, _owner.key, target, _isOperator, _id, _amount, target, "", _nonce, deadline
        );

        vm.expectRevert(abi.encodeWithSelector(ExpiredSignature.selector, deadline));
        erc6909.temporaryApproveAndCallBySig(
            _owner.addr, target, _isOperator, _id, _amount, target, "", _nonce, deadline, signature
        );
    }

    function testFuzz_temporaryApproveAndCallBySig_Revert_whenDoubleSpend(
        bool _isOperator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }

        address target = address(callback);

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            true, _owner.addr, _owner.key, target, _isOperator, _id, _amount, target, "", _nonce, deadline
        );

        erc6909.temporaryApproveAndCallBySig(
            _owner.addr, target, _isOperator, _id, _amount, target, "", _nonce, deadline, signature
        );

        vm.expectRevert(InvalidNonce.selector);
        erc6909.temporaryApproveAndCallBySig(
            _owner.addr, target, _isOperator, _id, _amount, target, "", _nonce, deadline, signature
        );
    }

    function testFuzz_temporaryApproveAndCallBySig_Revert_whenCancelled(
        bool _isOperator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }

        address target = address(callback);

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            true, _owner.addr, _owner.key, target, _isOperator, _id, _amount, target, "", _nonce, deadline
        );

        vm.prank(_owner.addr);
        erc6909.invalidateNonce(_nonce);

        vm.expectRevert(InvalidNonce.selector);
        erc6909.temporaryApproveAndCallBySig(
            _owner.addr, target, _isOperator, _id, _amount, target, "", _nonce, deadline, signature
        );
    }

    function test_temporaryApproveAndCallBySig_Revert_whenInvalidPermitParams() public {
        Account memory _owner = ALICE;

        address target = address(callback);

        uint48 deadline = type(uint48).max;

        bytes memory signature =
            getPermitSignature(true, _owner.addr, _owner.key, target, true, 1, 1, target, "", 0, deadline);

        vm.expectRevert(InvalidPermitParams.selector);
        erc6909.temporaryApproveAndCallBySig(_owner.addr, target, true, 1, 1, target, "", 0, deadline, signature);
    }

    function test_temporaryApproveAndCallBySig_Revert_whenUsingApproveBySigSignature(
        address _spender,
        uint256 _id,
        bool _isOperator,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;

        address target = address(callback);

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, _isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        vm.expectRevert(InvalidSigner.selector);
        erc6909.temporaryApproveAndCallBySig(
            _owner.addr, _spender, _isOperator, _id, _value, target, "", _nonce, deadline, signature
        );
    }

    function testFuzz_approveBySig(
        address _spender,
        uint256 _id,
        bool _isOperator,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), true);

        if (_isOperator) {
            _id = 0;
            _value = 0;
        }

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, _isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        erc6909.approveBySig(_owner.addr, _spender, _isOperator, _id, _value, _nonce, deadline, signature);

        if (_isOperator) {
            assertEq(erc6909.isOperator(_owner.addr, _spender), true);
        } else {
            assertEq(erc6909.allowance(_owner.addr, _spender, _id), _value);
        }

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), false);
    }

    function testFuzz_approveBySig_Revert_whenExpired(
        address _spender,
        uint256 _id,
        bool _isOperator,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        Account memory _owner = ALICE;
        if (_isOperator) {
            _id = 0;
            _value = 0;
        }

        uint48 deadline = uint48(block.timestamp) - 1;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, _isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        vm.expectRevert(abi.encodeWithSelector(ExpiredSignature.selector, deadline));
        erc6909.approveBySig(_owner.addr, _spender, _isOperator, _id, _value, _nonce, deadline, signature);
    }

    function testFuzz_approveBySig_Revert_whenDoubleSpend(
        address _spender,
        uint256 _id,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        bool isOperator = false;

        Account memory _owner = ALICE;

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, _nonce, deadline, signature);

        vm.expectRevert(InvalidNonce.selector);
        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, _nonce, deadline, signature);
    }

    function testFuzz_approveBySig_Revert_whenCancelled(
        address _spender,
        uint256 _id,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        bool isOperator = false;

        Account memory _owner = ALICE;

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        vm.prank(_owner.addr);
        erc6909.invalidateNonce(_nonce);

        vm.expectRevert(InvalidNonce.selector);
        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, _nonce, deadline, signature);
    }

    function testFuzz_approveBySig_Revert_wehnInvalidPermitParams(
        address _spender,
        uint256 _id,
        uint256 _value,
        uint256 _nonce
    )
        public
    {
        vm.assume(_id != 0 || _value != 0);

        bool isOperator = true;

        Account memory _owner = ALICE;

        uint48 deadline = type(uint48).max;

        bytes memory signature = getPermitSignature(
            false, _owner.addr, _owner.key, _spender, isOperator, _id, _value, address(0), "", _nonce, deadline
        );

        vm.expectRevert(InvalidPermitParams.selector);
        erc6909.approveBySig(_owner.addr, _spender, isOperator, _id, _value, _nonce, deadline, signature);
    }

    function testFuzz_approveBySign_Revert_whenUsingTemoporaryApprovaAndCallSig(
        bool _isOperator,
        uint256 _id,
        uint256 _amount,
        uint256 _nonce,
        uint256 _initialApproval
    )
        public
    {
        Account memory _owner = ALICE;

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), true);

        if (_isOperator) {
            _id = 0;
            _amount = 0;
        }

        address target = address(callback);

        {
            vm.startPrank(_owner.addr);
            erc6909.approve(address(target), _id, _initialApproval);
            vm.stopPrank();
        }

        {
            bytes memory signature = getPermitSignature(
                true, _owner.addr, _owner.key, target, _isOperator, _id, _amount, target, "", _nonce, type(uint48).max
            );

            vm.expectRevert(InvalidSigner.selector);
            erc6909.approveBySig(_owner.addr, target, _isOperator, _id, _amount, _nonce, type(uint48).max, signature);
        }
    }

    function testFuzz_invalidateNonce(uint256 _nonce) public {
        Account memory _owner = ALICE;

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), true);

        vm.prank(_owner.addr);
        erc6909.invalidateNonce(_nonce);

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), false);
    }

    function testFuzz_invalidateNonce_whenNonceIsInvalid(uint256 _nonce) public {
        Account memory _owner = ALICE;

        vm.prank(_owner.addr);
        erc6909.invalidateNonce(_nonce);

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), false);

        vm.prank(_owner.addr);
        erc6909.invalidateNonce(_nonce);

        assertEq(erc6909.isValidNonce(_owner.addr, _nonce), false);
    }

    function onTemporaryApprove(
        address owner,
        bool isOperator,
        uint256 id,
        uint256 amount,
        bytes calldata
    )
        external
        view
        returns (bytes4)
    { }

    function getMask(uint256 _nonce) internal pure returns (uint256 word, uint256 bit) {
        word = _nonce >> 8;
        bit = 1 << uint8(_nonce);
    }
}
