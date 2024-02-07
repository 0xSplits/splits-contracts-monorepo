// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { Ownable } from "../../src/utils/Ownable.sol";
import { Wallet } from "../../src/utils/Wallet.sol";
import { BaseTest } from "../Base.t.sol";

contract WalleHandler is Wallet {
    constructor(address _owner) {
        __initWallet(_owner);
    }
}

contract WalletTest is BaseTest {
    event ExecCalls(Wallet.Call[] calls);

    WalleHandler private wallet;

    function setUp() public override {
        super.setUp();

        wallet = new WalleHandler(ALICE.addr);
    }

    function test_owner() public {
        assertEq(wallet.owner(), ALICE.addr);
    }

    function test_execCalls_empty() public {
        vm.expectEmit();
        emit ExecCalls(new Wallet.Call[](0));
        vm.prank(wallet.owner());
        wallet.execCalls(new Wallet.Call[](0));
    }

    function test_execCalls_payable() public {
        uint256 balance = BOB.addr.balance;
        Wallet.Call memory call = Wallet.Call(BOB.addr, 1, "");

        Wallet.Call[] memory calls = new Wallet.Call[](1);
        calls[0] = call;

        deal(wallet.owner(), 1);
        vm.prank(wallet.owner());
        wallet.execCalls{ value: 1 }(calls);

        assertEq(BOB.addr.balance, balance + 1);
    }

    function test_execCalls_transferOwnership() public {
        Wallet.Call memory call = Wallet.Call({
            to: address(wallet),
            value: 0,
            data: abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr)
        });

        Wallet.Call[] memory calls = new Wallet.Call[](1);
        calls[0] = call;

        vm.prank(wallet.owner());
        wallet.execCalls{ value: 0 }(calls);

        assertEq(wallet.owner(), BOB.addr);
    }

    function test_execCalls_Revert_Unauthorized() public {
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execCalls(new Wallet.Call[](0));
    }

    function test_execCalls_Revert_InvalidCall() public {
        vm.expectRevert();
        wallet.execCalls(new Wallet.Call[](1));
    }

    function test_execCalls_Revert_TargetNotContract() public {
        Wallet.Call memory call = Wallet.Call({
            to: address(BOB.addr),
            value: 0,
            data: abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr)
        });

        Wallet.Call[] memory calls = new Wallet.Call[](1);
        calls[0] = call;

        vm.prank(wallet.owner());
        vm.expectRevert(
            abi.encodeWithSelector(
                Wallet.InvalidCalldataForEOA.selector,
                0,
                BOB.addr,
                abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr)
            )
        );
        wallet.execCalls(calls);
    }
}
