// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Math } from "../../src/libraries/Math.sol";
import { BaseTest } from "../Base.t.sol";
import { ERC20 } from "../utils/ERC20.sol";
import { Fuzzer } from "../utils/Fuzzer.sol";

contract WarehouseTest is BaseTest, Fuzzer {
    using Math for uint256[];

    error InvalidAmount();
    error TokenNotSupported();
    error ZeroOwner();
    error WithdrawalPaused(address owner);
    error ReentrancyGuardReentrantCall();
    error FailedInnerCall();

    address token;
    address[] defaultTokens;

    function setUp() public override {
        super.setUp();
        token = address(usdc);

        defaultTokens.push(address(usdc));
        defaultTokens.push(address(weth));
        defaultTokens.push(native);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  TEST_NAME                                 */
    /* -------------------------------------------------------------------------- */

    function test_name_whenERC20_returnsWrappedERC20Name() public {
        assertEq(warehouse.name(tokenToId(address(usdc))), string.concat("Splits Wrapped ", usdc.name()));
    }

    function test_name_whenNativeToken_returnsWrappedName() public {
        assertEq(warehouse.name(warehouse.NATIVE_TOKEN_ID()), GAS_TOKEN_NAME);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 TEST_SYMBOL                                */
    /* -------------------------------------------------------------------------- */

    function test_symbol_whenERC20_returnsWrappedERC20Symbol() public {
        assertEq(warehouse.symbol(tokenToId(address(usdc))), string.concat("Splits", usdc.symbol()));
    }

    function test_symbol_whenNativeToken_returnsWrappedSymbol() public {
        assertEq(warehouse.symbol(warehouse.NATIVE_TOKEN_ID()), GAS_TOKEN_SYMBOL);
    }

    /* -------------------------------------------------------------------------- */
    /*                                TEST_DECIMALS                               */
    /* -------------------------------------------------------------------------- */

    function test_decimals_whenERC20_returnsERC20Decimals() public {
        assertEq(warehouse.decimals(tokenToId(address(usdc))), usdc.decimals());
    }

    function test_decimals_whenNativeToken_returns18() public {
        assertEq(warehouse.decimals(warehouse.NATIVE_TOKEN_ID()), 18);
    }

    /* -------------------------------------------------------------------------- */
    /*                          TEST_DEPOSIT_SINGLE_OWNER                         */
    /* -------------------------------------------------------------------------- */

    function testFuzz_depositSingleOwner_whenERC20(address _depositor, address _owner, uint256 _amount) public {
        vm.assume(_depositor != address(0) && _owner != address(0));

        deal(token, _depositor, _amount);

        vm.startPrank(_depositor);
        ERC20(token).approve(address(warehouse), _amount);
        warehouse.deposit(_owner, address(usdc), _amount);
        vm.stopPrank();

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(token)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(token)), ERC20(token).balanceOf(address(warehouse)));
    }

    function testFuzz_depositSingleOwner_whenNativeToken(address _depositor, address _owner, uint256 _amount) public {
        vm.assume(_depositor != address(0) && _owner != address(0));

        deal(_depositor, _amount);

        vm.startPrank(_depositor);
        warehouse.deposit{ value: _amount }(_owner, native, _amount);
        vm.stopPrank();

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(native)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(native)), address(warehouse).balance);
    }

    function test_depositSingleOwner_whenNativeToken_Revert_whenAmountIsNotEqualToValue() public {
        vm.expectRevert(InvalidAmount.selector);
        warehouse.deposit{ value: 100 ether }(msg.sender, native, 99 ether);

        assertEq(warehouse.balanceOf(msg.sender, tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), address(warehouse).balance);
    }

    function test_depositSingleOwner_whenNativeToken_Revert_whenOwnerIsZero() public {
        vm.assume(msg.sender != address(0));

        vm.expectRevert(ZeroOwner.selector);
        warehouse.deposit{ value: 100 ether }(address(0), native, 100 ether);

        assertEq(warehouse.balanceOf(address(0), tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), address(warehouse).balance);
    }

    function test_depositSingleOwner_Revert_whenNonERC20() public {
        vm.expectRevert();
        warehouse.deposit(msg.sender, address(this), 100 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                        TEST_DEPOSIT_MULTIPLE_OWNERS                        */
    /* -------------------------------------------------------------------------- */

    function testFuzz_depositMultipleOwners_whenERC20(
        address _depositor,
        address[1000] memory _owners,
        uint96[1000] memory _amounts
    )
        public
    {
        vm.assume(_depositor != address(0));
        (address[] memory owners, uint256[] memory amounts) = fuzzMultipleOwnerDeposits(_owners, _amounts);
        uint256 totalAmounts = amounts.sumMem();

        deal(token, _depositor, totalAmounts);

        vm.startPrank(_depositor);
        ERC20(token).approve(address(warehouse), totalAmounts);
        warehouse.deposit(owners, token, amounts);
        vm.stopPrank();

        for (uint256 i = 0; i < owners.length; i++) {
            assertGte(warehouse.balanceOf(owners[i], tokenToId(token)), amounts[i]);
        }
        assertEq(warehouse.totalSupply(tokenToId(token)), totalAmounts);
        assertEq(warehouse.totalSupply(tokenToId(token)), ERC20(token).balanceOf(address(warehouse)));
    }

    function testFuzz_depositMultipleOwners_whenNativeToken(
        address _depositor,
        address[1000] memory _owners,
        uint96[1000] memory _amounts
    )
        public
    {
        vm.assume(_depositor != address(0));
        (address[] memory owners, uint256[] memory amounts) = fuzzMultipleOwnerDeposits(_owners, _amounts);
        uint256 totalAmounts = amounts.sumMem();

        deal(_depositor, totalAmounts);

        vm.startPrank(_depositor);
        warehouse.deposit{ value: totalAmounts }(owners, native, amounts);
        vm.stopPrank();

        for (uint256 i = 0; i < owners.length; i++) {
            assertGte(warehouse.balanceOf(owners[i], tokenToId(native)), amounts[i]);
        }
        assertEq(warehouse.totalSupply(tokenToId(native)), totalAmounts);
        assertEq(warehouse.totalSupply(tokenToId(native)), address(warehouse).balance);
    }

    function test_depositMultipleOwners_Revert_whenOwnerAmountsMismatch() public {
        address[] memory _owners = new address[](2);
        uint256[] memory _amounts = new uint256[](1);

        vm.expectRevert(LengthMismatch.selector);
        warehouse.deposit(_owners, token, _amounts);
    }

    function test_depositMultipleOwners_whenNativeToken_Revert_whenAmountIsNotEqualToValue() public {
        vm.expectRevert(InvalidAmount.selector);
        warehouse.deposit{ value: 100 ether }(new address[](1), native, new uint256[](1));
    }

    function test_depositMultipleOwners_Revert_whenOwnerIsZero() public {
        address[] memory _owners = new address[](1);
        uint256[] memory _amounts = new uint256[](1);
        _amounts[0] = 100 ether;

        vm.expectRevert(ZeroOwner.selector);
        warehouse.deposit{ value: 100 ether }(_owners, native, _amounts);
    }

    function test_depositMultipleOwners_Revert_whenNonERC20() public {
        vm.expectRevert();
        warehouse.deposit(new address[](1), address(this), new uint256[](1));
    }

    /* -------------------------------------------------------------------------- */
    /*                  TEST_DEPOSIT_AFTER_TRANSFER_SINGLE_OWNER                  */
    /* -------------------------------------------------------------------------- */

    function testFuzz_depositAfterTransferSingleOwner_whenERC20(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0));

        deal(token, _owner, _amount);

        vm.prank(_owner);
        ERC20(token).transfer(address(warehouse), _amount);

        warehouse.depositAfterTransfer(_owner, token, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(token)), _amount);
        assertEq(warehouse.totalSupply(tokenToId(token)), ERC20(token).balanceOf(address(warehouse)));
    }

    function test_depositAfterTransferSingleOwner_Reverts_whenNativeToken() public {
        vm.expectRevert(TokenNotSupported.selector);
        warehouse.depositAfterTransfer(address(0), native, 0);
    }

    function test_depositAfterTransferSingleOwner_whenERC20_Reverts_whenAmountIsGreaterThanBalance() public {
        deal(token, msg.sender, 100 ether);

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), 100 ether);

        vm.expectRevert(InvalidAmount.selector);
        warehouse.depositAfterTransfer(msg.sender, token, 101 ether);
    }

    function test_depositAfterTransferSingleOwner_whenERC20_Reverts_whenOwnerIsZero() public {
        deal(token, msg.sender, 100 ether);

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), 100 ether);

        vm.expectRevert(ZeroOwner.selector);
        warehouse.depositAfterTransfer(address(0), token, 100 ether);
    }

    function test_depositAfterTransferSingleOwner_Reverts_whenNonERC20() public {
        vm.expectRevert();
        warehouse.depositAfterTransfer(address(0), address(this), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                 TEST_DEPOSIT_AFTER_TRANSFER_MULTIPLE_OWNERS                */
    /* -------------------------------------------------------------------------- */

    function testFuzz_depositAfterTransferMultipleOwners_whenERC20(
        address[1000] memory _owners,
        uint96[1000] memory _amounts
    )
        public
    {
        (address[] memory owners, uint256[] memory amounts) = fuzzMultipleOwnerDeposits(_owners, _amounts);
        uint256 totalAmounts = amounts.sumMem();

        deal(token, msg.sender, totalAmounts);

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), totalAmounts);

        warehouse.depositAfterTransfer(owners, token, amounts);

        for (uint256 i = 0; i < owners.length; i++) {
            assertGte(warehouse.balanceOf(owners[i], tokenToId(token)), amounts[i]);
        }
        assertEq(warehouse.totalSupply(tokenToId(token)), totalAmounts);
        assertEq(warehouse.totalSupply(tokenToId(token)), ERC20(token).balanceOf(address(warehouse)));
    }

    function test_depositAfterTransferMultipleOwners_Reverts_whenNativeToken() public {
        vm.expectRevert(TokenNotSupported.selector);
        warehouse.depositAfterTransfer(new address[](1), native, new uint256[](1));
    }

    function test_depositAfterTransferMultipleOwners_whenERC20_Reverts_whenAmountIsGreaterThanBalance() public {
        deal(token, msg.sender, 100 ether);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 101 ether;

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), 100 ether);

        vm.expectRevert(InvalidAmount.selector);
        warehouse.depositAfterTransfer(new address[](1), token, amounts);
    }

    function test_depositAfterTransferMultipleOwners_Reverts_whenOwnerAmountsMismatch() public {
        address[] memory _owners = new address[](2);
        uint256[] memory _amounts = new uint256[](1);

        deal(token, msg.sender, 100 ether);

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), 100 ether);

        vm.expectRevert(LengthMismatch.selector);
        warehouse.depositAfterTransfer(_owners, token, _amounts);
    }

    function test_depositAfterTransferMultipleOwners_whenERC20_Reverts_whenOwnerIsZero() public {
        deal(token, msg.sender, 100 ether);

        vm.prank(msg.sender);
        ERC20(token).transfer(address(warehouse), 100 ether);

        vm.expectRevert(ZeroOwner.selector);
        warehouse.depositAfterTransfer(new address[](1), token, new uint256[](1));
    }

    function test_depositAfterTransferMultipleOwners_Reverts_whenNonERC20() public {
        vm.expectRevert();
        warehouse.depositAfterTransfer(new address[](1), address(this), new uint256[](1));
    }

    /* -------------------------------------------------------------------------- */
    /*                             TEST_WITHDRAW_OWNER                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawOwner_whenERC20(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0));

        testFuzz_depositSingleOwner_whenERC20(_owner, _owner, _amount);

        vm.prank(_owner);
        warehouse.withdraw(token, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), 0);
        assertEq(warehouse.totalSupply(tokenToId(token)), 0);
    }

    function testFuzz_withdrawOwner_whenNative(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0) && _owner.code.length == 0);

        testFuzz_depositSingleOwner_whenNativeToken(_owner, _owner, _amount);

        vm.prank(_owner);
        warehouse.withdraw(native, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), 0);
    }

    function test_withdrawOwner_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(token, 101 ether);

        assertEq(warehouse.balanceOf(owner, tokenToId(token)), 100 ether);
        assertEq(warehouse.totalSupply(tokenToId(token)), 100 ether);
    }

    function test_withdrawOwner_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        testFuzz_depositSingleOwner_whenNativeToken(owner, owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert(FailedInnerCall.selector);
        warehouse.withdraw(native, 100 ether);

        assertEq(warehouse.balanceOf(owner, tokenToId(native)), 100 ether);
        assertEq(warehouse.totalSupply(tokenToId(native)), 100 ether);
    }

    function test_withdrawOwner_Revert_whenNonERC20() public {
        address owner = ALICE;

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(address(this), 100 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                     TEST_WITHDRAW_OWNER_MULTIPLE_TOKENS                    */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawOwner_multipleTokens(uint256 _amount) public {
        address owner = ALICE;

        depositDefaultTokens(owner, _amount);

        vm.prank(owner);
        warehouse.withdraw(defaultTokens, getAmounts(_amount));

        for (uint256 i = 0; i < defaultTokens.length; i++) {
            assertEq(warehouse.balanceOf(owner, tokenToId(defaultTokens[i])), 0);
            assertEq(warehouse.totalSupply(tokenToId(defaultTokens[i])), 0);
        }
    }

    function test_withdrawOwner_multipleTokens_Revert_whenLengthMismatch() public {
        address owner = ALICE;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert(LengthMismatch.selector);
        warehouse.withdraw(defaultTokens, new uint256[](1));
    }

    function test_withdrawOwner_multipleTokens_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(defaultTokens, getAmounts(101 ether));
    }

    function test_withdrawOwner_multipleTokens_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert(FailedInnerCall.selector);
        warehouse.withdraw(defaultTokens, getAmounts(100 ether));
    }

    /* -------------------------------------------------------------------------- */
    /*                       WITHDRAW_FOR_OWNER_SINGLE_TOKEN                      */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawForOwner_singleToken_whenERC20(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0));

        testFuzz_depositSingleOwner_whenERC20(_owner, _owner, _amount);

        warehouse.withdraw(_owner, token, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), 0);
        assertEq(warehouse.totalSupply(tokenToId(token)), 0);
        assertEq(ERC20(token).balanceOf(_owner), _amount);
    }

    function testFuzz_withdrawForOwner_singleToken_whenNative(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0) && _owner.code.length == 0);

        testFuzz_depositSingleOwner_whenNativeToken(_owner, _owner, _amount);

        warehouse.withdraw(_owner, native, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), 0);
        assertEq(warehouse.totalSupply(tokenToId(native)), 0);
        assertEq(address(_owner).balance, _amount);
    }

    function test_withdrawForOwner_singleToken_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        vm.expectRevert();
        warehouse.withdraw(owner, token, 101 ether);
    }

    function test_withdrawForOwner_singleToken_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        testFuzz_depositSingleOwner_whenNativeToken(owner, owner, 100 ether);

        vm.expectRevert(FailedInnerCall.selector);
        warehouse.withdraw(owner, native, 100 ether);
    }

    function test_withdrawForOwner_singleToken_Revert_whenNonERC20() public {
        address owner = ALICE;

        vm.expectRevert();
        warehouse.withdraw(owner, address(this), 100 ether);
    }

    function test_withdrawForOwner_singleToken_Revert_whenWithdrawalPaused() public {
        address owner = ALICE;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        vm.startPrank(owner);
        warehouse.pauseWithdrawals(true);

        vm.expectRevert(abi.encodeWithSelector(WithdrawalPaused.selector, owner));
        warehouse.withdraw(owner, token, 100 ether);
        vm.stopPrank();
    }

    function test_withdrawForOwner_singleToken_Revert_whenZeroOwner() public {
        vm.expectRevert(ZeroOwner.selector);
        warehouse.withdraw(address(0), token, 100 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                     WITHDRAW_FOR_OWNER_MULTIPLE_TOKENS                     */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawForOwner_multipleTokens(address _owner, uint256 _amount) public {
        vm.assume(_owner != address(0) && _owner.code.length == 0);

        depositDefaultTokens(_owner, _amount);

        warehouse.withdraw(_owner, defaultTokens, getAmounts(_amount));

        for (uint256 i = 0; i < defaultTokens.length; i++) {
            assertEq(warehouse.balanceOf(_owner, tokenToId(defaultTokens[i])), 0);
            assertEq(warehouse.totalSupply(tokenToId(defaultTokens[i])), 0);

            if (defaultTokens[i] == native) {
                assertEq(address(_owner).balance, _amount);
            } else {
                assertEq(ERC20(defaultTokens[i]).balanceOf(_owner), _amount);
            }
        }
    }

    function testFuzz_withdrawForOwner_multipleTokens_Revert_whenLengthMismatch() public {
        address owner = ALICE;

        vm.expectRevert(LengthMismatch.selector);
        warehouse.withdraw(owner, defaultTokens, new uint256[](1));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE;

        depositDefaultTokens(owner, 100 ether);

        vm.expectRevert();
        warehouse.withdraw(owner, defaultTokens, getAmounts(101 ether));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        depositDefaultTokens(owner, 100 ether);

        vm.expectRevert(FailedInnerCall.selector);
        warehouse.withdraw(owner, defaultTokens, getAmounts(100 ether));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenNonERC20() public {
        address owner = ALICE;

        vm.expectRevert();
        warehouse.withdraw(owner, new address[](1), new uint256[](1));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenWithdrawalPaused() public {
        address owner = ALICE;

        depositDefaultTokens(owner, 100 ether);

        vm.startPrank(owner);
        warehouse.pauseWithdrawals(true);

        vm.expectRevert(abi.encodeWithSelector(WithdrawalPaused.selector, owner));
        warehouse.withdraw(owner, defaultTokens, getAmounts(100 ether));
        vm.stopPrank();
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenZeroOwner() public {
        vm.expectRevert(ZeroOwner.selector);
        warehouse.withdraw(address(0), defaultTokens, getAmounts(100 ether));
    }

    /* -------------------------------------------------------------------------- */
    /*                                OWNER_ACTIONS                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_pauseWithdrawals(address _owner, bool pause) public {
        vm.assume(_owner != address(0));

        vm.prank(_owner);
        warehouse.pauseWithdrawals(pause);

        assertEq(warehouse.isWithdrawPaused(_owner), pause);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  UTILITIES                                 */
    /* -------------------------------------------------------------------------- */

    function getAmounts(uint256 _amount) internal view returns (uint256[] memory amounts) {
        amounts = new uint256[](defaultTokens.length);
        for (uint256 i = 0; i < defaultTokens.length; i++) {
            amounts[i] = _amount;
        }
    }

    function depositDefaultTokens(address _owner, uint256 _amount) internal {
        for (uint256 i = 0; i < defaultTokens.length; i++) {
            deposit(_owner, defaultTokens[i], _amount);
        }
    }

    function deposit(address _owner, address _token, uint256 _amount) internal {
        if (_token == native) {
            deal(_owner, _amount);
        } else {
            deal(_token, _owner, _amount);
        }

        vm.startPrank(_owner);
        if (_token == native) {
            warehouse.deposit{ value: _amount }(_owner, _token, _amount);
        } else {
            ERC20(_token).approve(address(warehouse), _amount);
            warehouse.deposit(_owner, _token, _amount);
        }
        vm.stopPrank();
    }
}
