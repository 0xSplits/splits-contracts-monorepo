// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Ownable } from "../../src/utils/Ownable.sol";
import { Wallet } from "../../src/utils/Wallet.sol";
import { BaseTest } from "../Base.t.sol";

import { MockERC1155 } from "../mocks/MockERC1155.sol";
import { MockERC721 } from "../mocks/MockERC721.sol";

contract WalleHandler is Wallet {
    constructor(address _owner) {
        __initWallet(_owner);
    }
}

contract WalletTest is BaseTest {
    event ExecCalls(Wallet.Call[] calls);

    WalleHandler private wallet;

    MockERC1155 erc1155;
    MockERC721 erc721;

    function setUp() public override {
        super.setUp();

        wallet = new WalleHandler(ALICE.addr);
        erc1155 = new MockERC1155();
        erc721 = new MockERC721();
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

    function test_execCalls_Revert_afterTransferOwnership() public {
        Wallet.Call memory call = Wallet.Call({
            to: address(wallet),
            value: 0,
            data: abi.encodeWithSelector(Ownable.transferOwnership.selector, BOB.addr)
        });

        Wallet.Call[] memory calls = new Wallet.Call[](2);
        calls[0] = call;

        vm.prank(wallet.owner());
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execCalls{ value: 0 }(calls);
    }

    function test_execCalls_Revert_Unauthorized() public {
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.execCalls(new Wallet.Call[](1));
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
        vm.expectRevert(abi.encodeWithSelector(Wallet.InvalidCalldataForEOA.selector, call));
        wallet.execCalls(calls);
    }

    function testFuzz_receive_erc721(uint256 _id) public {
        erc721.safeMint(address(wallet), _id);
    }

    function testFuzz_receive_erc1155(uint256 _id, uint256 _amount) public {
        erc1155.mint(address(wallet), _id, _amount, "");
    }

    struct MintERC1155 {
        uint96 id;
        uint96 amount;
    }

    function testFuzz_batchReceive_erc1155(MintERC1155[] calldata _mints) public {
        uint256[] memory ids = new uint256[](_mints.length);
        uint256[] memory amounts = new uint256[](_mints.length);
        for (uint256 i; i < _mints.length; i++) {
            ids[i] = _mints[i].id;
            amounts[i] = _mints[i].amount;
        }
        erc1155.batchMint(address(wallet), ids, amounts, "");
    }
}
