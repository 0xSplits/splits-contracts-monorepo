// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { SplitsWarehouse } from "../../src/SplitsWarehouse.sol";
import { Math } from "../../src/libraries/Math.sol";
import { BaseTest } from "../Base.t.sol";
import { ERC20 } from "../utils/ERC20.sol";
import { Fuzzer } from "../utils/Fuzzer.sol";

contract SplitsWarehouseTest is BaseTest, Fuzzer {
    using Math for uint256[];

    error InvalidAmount();
    error ZeroOwner();
    error WithdrawalPaused(address owner);
    error ReentrancyGuardReentrantCall();
    error FailedInnerCall();
    error CastOverflow(uint256 value);

    address public token;
    address[] public defaultTokens;

    function setUp() public override {
        super.setUp();
        token = address(usdc);

        defaultTokens.push(address(usdc));
        defaultTokens.push(address(weth));
        defaultTokens.push(native);

        assumeAddresses.push(address(this));
        assumeAddresses.push(address(BAD_ACTOR));
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

    function test_name_Revert_whenTokenIDGreaterThanUint160() public {
        uint256 tokenId = uint256(type(uint160).max) + 1;
        vm.expectRevert(abi.encodeWithSelector(CastOverflow.selector, tokenId));
        warehouse.name(tokenId);
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

    function test_symbol_Revert_whenTokenIDGreaterThanUint160() public {
        uint256 tokenId = uint256(type(uint160).max) + 1;
        vm.expectRevert(abi.encodeWithSelector(CastOverflow.selector, tokenId));
        warehouse.symbol(tokenId);
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

    function test_decimals_Revert_whenTokenIDGreaterThanUint160() public {
        uint256 tokenId = uint256(type(uint160).max) + 1;
        vm.expectRevert(abi.encodeWithSelector(CastOverflow.selector, tokenId));
        warehouse.decimals(tokenId);
    }

    /* -------------------------------------------------------------------------- */
    /*                          TEST_DEPOSIT_SINGLE_OWNER                         */
    /* -------------------------------------------------------------------------- */

    function testFuzz_depositSingleOwner_whenERC20(address _depositor, address _owner, uint256 _amount) public {
        assumeAddress(_depositor);
        assumeAddress(_owner);

        deal(token, _depositor, _amount);

        vm.startPrank(_depositor);
        ERC20(token).approve(address(warehouse), _amount);
        warehouse.deposit(_owner, address(usdc), _amount);
        vm.stopPrank();

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), _amount);
        assertEq(ERC20(token).balanceOf(address(warehouse)), _amount);
    }

    function testFuzz_depositSingleOwner_whenNativeToken(address _depositor, address _owner, uint256 _amount) public {
        assumeAddress(_depositor);
        assumeAddress(_owner);

        deal(_depositor, _amount);

        vm.startPrank(_depositor);
        warehouse.deposit{ value: _amount }(_owner, native, _amount);
        vm.stopPrank();

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), _amount);
        assertEq(address(warehouse).balance, _amount);
    }

    function test_depositSingleOwner_whenNativeToken_Revert_whenAmountIsNotEqualToValue() public {
        vm.expectRevert(InvalidAmount.selector);
        warehouse.deposit{ value: 100 ether }(msg.sender, native, 99 ether);
    }

    function test_depositSingleOwner_whenNativeToken_Revert_whenOwnerIsZero() public {
        vm.assume(msg.sender != address(0));

        vm.expectRevert(ZeroOwner.selector);
        warehouse.deposit{ value: 100 ether }(address(0), native, 100 ether);
    }

    function test_depositSingleOwner_Revert_whenNonERC20() public {
        vm.expectRevert();
        warehouse.deposit(msg.sender, address(this), 100 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                             TEST_WITHDRAW_OWNER                            */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawOwner_whenERC20(address _owner, uint256 _amount) public {
        assumeAddress(_owner);

        testFuzz_depositSingleOwner_whenERC20(_owner, _owner, _amount);

        vm.prank(_owner);
        warehouse.withdraw(token, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), 0);
        assertEq(ERC20(token).balanceOf(address(warehouse)), 0);
    }

    function testFuzz_withdrawOwner_whenNative(address _owner, uint256 _amount) public {
        assumeAddress(_owner);

        testFuzz_depositSingleOwner_whenNativeToken(_owner, _owner, _amount);

        vm.prank(_owner);
        warehouse.withdraw(native, _amount);

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), 0);
        assertEq(address(warehouse).balance, 0);
    }

    function test_withdrawOwner_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE.addr;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(token, 101 ether);
    }

    function test_withdrawOwner_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        deposit(owner, native, 100 ether);

        vm.prank(owner);
        vm.expectRevert("Address: unable to send value, recipient may have reverted");
        warehouse.withdraw(native, 100 ether);
    }

    function test_withdrawOwner_Revert_whenNonERC20() public {
        address owner = ALICE.addr;

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(address(this), 100 ether);
    }

    /* -------------------------------------------------------------------------- */
    /*                     TEST_WITHDRAW_OWNER_MULTIPLE_TOKENS                    */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawOwner_multipleTokens(uint256 _amount) public {
        address owner = ALICE.addr;

        depositDefaultTokens(owner, _amount);

        vm.prank(owner);
        warehouse.withdraw(defaultTokens, getAmounts(_amount));

        for (uint256 i = 0; i < defaultTokens.length; i++) {
            assertEq(warehouse.balanceOf(owner, tokenToId(defaultTokens[i])), 0);
            if (defaultTokens[i] == native) {
                assertEq(address(warehouse).balance, 0);
            } else {
                assertEq(ERC20(defaultTokens[i]).balanceOf(address(warehouse)), 0);
            }
        }
    }

    function test_withdrawOwner_multipleTokens_Revert_whenLengthMismatch() public {
        address owner = ALICE.addr;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert(LengthMismatch.selector);
        warehouse.withdraw(defaultTokens, new uint256[](1));
    }

    function test_withdrawOwner_multipleTokens_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE.addr;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert();
        warehouse.withdraw(defaultTokens, getAmounts(101 ether));
    }

    function test_withdrawOwner_multipleTokens_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        depositDefaultTokens(owner, 100 ether);

        vm.prank(owner);
        vm.expectRevert("Address: unable to send value, recipient may have reverted");
        warehouse.withdraw(defaultTokens, getAmounts(100 ether));
    }

    /* -------------------------------------------------------------------------- */
    /*                       WITHDRAW_FOR_OWNER_SINGLE_TOKEN                      */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawForOwner_singleToken_whenERC20(address _owner, uint256 _amount) public {
        assumeAddress(_owner);

        testFuzz_depositSingleOwner_whenERC20(_owner, _owner, _amount);

        warehouse.withdraw(_owner, token, _amount, address(this));

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), 0);
        assertEq(ERC20(token).balanceOf(_owner), _amount);
        assertEq(ERC20(token).balanceOf(address(warehouse)), 0);
    }

    function testFuzz_withdrawForOwner_singleToken_whenNative(address _owner, uint256 _amount) public {
        assumeAddress(_owner);

        testFuzz_depositSingleOwner_whenNativeToken(_owner, _owner, _amount);

        warehouse.withdraw(_owner, native, _amount, address(this));

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), 0);
        assertEq(address(_owner).balance, _amount);
        assertEq(address(warehouse).balance, 0);
    }

    function test_withdrawForOwner_singleToken_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE.addr;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        vm.expectRevert();
        warehouse.withdraw(owner, token, 101 ether, address(this));
    }

    function test_withdrawForOwner_singleToken_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        deposit(BAD_ACTOR, native, 1 ether);

        vm.expectRevert("Address: unable to send value, recipient may have reverted");
        warehouse.withdraw(owner, native, 1 ether, address(this));
    }

    function test_withdrawForOwner_singleToken_Revert_whenNonERC20() public {
        address owner = ALICE.addr;

        vm.expectRevert();
        warehouse.withdraw(owner, address(this), 100 ether, address(this));
    }

    function test_withdrawForOwner_singleToken_Revert_whenWithdrawalPaused() public {
        address owner = ALICE.addr;

        testFuzz_depositSingleOwner_whenERC20(owner, owner, 100 ether);

        SplitsWarehouse.WithdrawConfig memory config = SplitsWarehouse.WithdrawConfig({ incentive: 0, paused: true });

        vm.startPrank(owner);
        warehouse.setWithdrawConfig(config);

        vm.expectRevert(abi.encodeWithSelector(WithdrawalPaused.selector, owner));
        warehouse.withdraw(owner, token, 100 ether, address(this));
        vm.stopPrank();
    }

    function test_withdrawForOwner_singleToken_Revert_whenZeroOwner() public {
        vm.expectRevert(ZeroOwner.selector);
        warehouse.withdraw(address(0), token, 100 ether, address(this));
    }

    function testFuzz_withdrawForOwner_singleToken_whenERC20WithIncentive(
        address _owner,
        uint192 _amount,
        uint16 _incentive,
        address _withdrawer
    )
        public
    {
        assumeAddress(_owner);
        assumeAddress(_withdrawer);
        vm.assume(_owner != _withdrawer);
        vm.assume(_withdrawer.balance == 0);

        testFuzz_depositSingleOwner_whenERC20(_owner, _owner, _amount);
        testFuzz_setWithdrawalConfig(_owner, SplitsWarehouse.WithdrawConfig({ incentive: _incentive, paused: false }));

        uint256 reward = uint256(_amount) * uint256(_incentive) / warehouse.PERCENTAGE_SCALE();

        warehouse.withdraw(_owner, token, _amount, _withdrawer);

        assertEq(warehouse.balanceOf(_owner, tokenToId(token)), 0);
        assertEq(ERC20(token).balanceOf(_owner), _amount - reward);
        assertEq(ERC20(token).balanceOf(_withdrawer), reward);
        assertEq(ERC20(token).balanceOf(address(warehouse)), 0);
    }

    function testFuzz_withdrawForOwner_singleToken_whenNativeWithIncentive(
        address _owner,
        uint192 _amount,
        uint16 _incentive,
        address _withdrawer
    )
        public
    {
        assumeAddress(_owner);
        assumeAddress(_withdrawer);
        vm.assume(_owner != _withdrawer);
        vm.assume(_withdrawer.balance == 0);

        testFuzz_depositSingleOwner_whenNativeToken(_owner, _owner, _amount);
        testFuzz_setWithdrawalConfig(_owner, SplitsWarehouse.WithdrawConfig({ incentive: _incentive, paused: false }));

        uint256 reward = uint256(_amount) * uint256(_incentive) / warehouse.PERCENTAGE_SCALE();

        warehouse.withdraw(_owner, native, _amount, _withdrawer);

        assertEq(warehouse.balanceOf(_owner, tokenToId(native)), 0);
        assertEq(address(_owner).balance, _amount - reward);
        assertEq(_withdrawer.balance, reward);
        assertEq(address(warehouse).balance, 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                     WITHDRAW_FOR_OWNER_MULTIPLE_TOKENS                     */
    /* -------------------------------------------------------------------------- */

    function testFuzz_withdrawForOwner_multipleTokens(address _owner, uint256 _amount) public {
        assumeAddress(_owner);

        depositDefaultTokens(_owner, _amount);

        warehouse.withdraw(_owner, defaultTokens, getAmounts(_amount), address(this));

        for (uint256 i = 0; i < defaultTokens.length; i++) {
            assertEq(warehouse.balanceOf(_owner, tokenToId(defaultTokens[i])), 0);

            if (defaultTokens[i] == native) {
                assertEq(address(_owner).balance, _amount);
                assertEq(address(warehouse).balance, 0);
            } else {
                assertEq(ERC20(defaultTokens[i]).balanceOf(_owner), _amount);
                assertEq(ERC20(defaultTokens[i]).balanceOf(address(warehouse)), 0);
            }
        }
    }

    function testFuzz_withdrawForOwner_multipleTokens_Revert_whenLengthMismatch() public {
        address owner = ALICE.addr;

        vm.expectRevert(LengthMismatch.selector);
        warehouse.withdraw(owner, defaultTokens, new uint256[](1), address(this));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenWithdrawGreaterThanBalance() public {
        address owner = ALICE.addr;

        depositDefaultTokens(owner, 100 ether);

        vm.expectRevert();
        warehouse.withdraw(owner, defaultTokens, getAmounts(101 ether), address(this));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenOwnerReenters() public {
        address owner = BAD_ACTOR;

        depositDefaultTokens(owner, 100 ether);

        vm.expectRevert("Address: unable to send value, recipient may have reverted");
        warehouse.withdraw(owner, defaultTokens, getAmounts(100 ether), address(this));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenNonERC20() public {
        address owner = ALICE.addr;

        vm.expectRevert();
        warehouse.withdraw(owner, new address[](1), new uint256[](1), address(this));
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenWithdrawalPaused() public {
        address owner = ALICE.addr;

        depositDefaultTokens(owner, 100 ether);

        SplitsWarehouse.WithdrawConfig memory config = SplitsWarehouse.WithdrawConfig({ incentive: 0, paused: true });

        vm.startPrank(owner);
        warehouse.setWithdrawConfig(config);

        vm.expectRevert(abi.encodeWithSelector(WithdrawalPaused.selector, owner));
        warehouse.withdraw(owner, defaultTokens, getAmounts(100 ether), address(this));
        vm.stopPrank();
    }

    function test_withdrawForOwner_multipleTokens_Revert_whenZeroOwner() public {
        vm.expectRevert(ZeroOwner.selector);
        warehouse.withdraw(address(0), defaultTokens, getAmounts(100 ether), address(this));
    }

    function testFuzz_withdrawWithIncentiveForOwner_multipleTokens(
        address _owner,
        uint192 _amount,
        uint16 _incentive,
        address _withdrawer
    )
        public
    {
        assumeAddress(_owner);
        assumeAddress(_withdrawer);
        vm.assume(_owner != _withdrawer);
        vm.assume(_withdrawer.balance == 0);

        depositDefaultTokens(_owner, _amount);
        testFuzz_setWithdrawalConfig(_owner, SplitsWarehouse.WithdrawConfig({ incentive: _incentive, paused: false }));

        warehouse.withdraw(_owner, defaultTokens, getAmounts(_amount), _withdrawer);

        for (uint256 i = 0; i < defaultTokens.length; i++) {
            assertEq(warehouse.balanceOf(_owner, tokenToId(defaultTokens[i])), 0);

            uint256 reward = uint256(_amount) * _incentive / warehouse.PERCENTAGE_SCALE();

            if (defaultTokens[i] == native) {
                assertEq(address(_owner).balance, _amount - reward);
                assertEq(_withdrawer.balance, reward);
                assertEq(address(warehouse).balance, 0);
            } else {
                assertEq(ERC20(defaultTokens[i]).balanceOf(_owner), _amount - reward);
                assertEq(ERC20(defaultTokens[i]).balanceOf(_withdrawer), reward);
                assertEq(ERC20(defaultTokens[i]).balanceOf(address(warehouse)), 0);
            }
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                OWNER_ACTIONS                               */
    /* -------------------------------------------------------------------------- */

    function testFuzz_setWithdrawalConfig(address _owner, SplitsWarehouse.WithdrawConfig memory _config) public {
        vm.prank(_owner);
        warehouse.setWithdrawConfig(_config);

        SplitsWarehouse.WithdrawConfig memory config = warehouse.getWithdrawConfig(_owner);

        assertEq(config.paused, _config.paused);
        assertEq(config.incentive, _config.incentive);
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
