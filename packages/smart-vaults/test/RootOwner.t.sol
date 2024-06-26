// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";
import { RootOwnerMock } from "./mocks/RootOwnerMock.sol";
import { LibClone } from "solady/utils/LibClone.sol";

contract RootOwnerTest is BaseTest {
    RootOwnerMock rootOwner;
    RootOwnerMock rootOwnerProxy;

    event Transfer();

    error OnlyRoot();

    function setUp() public override {
        super.setUp();

        rootOwner = new RootOwnerMock();
        rootOwnerProxy = RootOwnerMock(LibClone.clone(address(rootOwner)));

        rootOwner.initialize(ALICE.addr);
        rootOwnerProxy.initialize(BOB.addr);
    }

    function getRootOwner(bool proxy) private view returns (RootOwnerMock) {
        return proxy ? rootOwnerProxy : rootOwner;
    }

    function getOwner(bool proxy) private view returns (address) {
        return proxy ? BOB.addr : ALICE.addr;
    }

    function test_rootOwner_is_ALICE() public {
        assertEq(rootOwner.root(), ALICE.addr);
    }

    function test_rootOwnerProxy_is_BOB() public {
        assertEq(rootOwnerProxy.root(), BOB.addr);
    }

    function testFuzz_transferRoot(bool proxy) public {
        vm.startPrank(getOwner(proxy));
        vm.expectEmit();
        emit Transfer();
        getRootOwner(proxy).transferRoot();
        vm.stopPrank();
    }

    function testFuzz_transferRoot_RevertWhen_NotOwner(bool proxy, address owner) public {
        vm.assume(owner != ALICE.addr && owner != BOB.addr);

        vm.startPrank(owner);
        vm.expectRevert(OnlyRoot.selector);
        getRootOwner(proxy).transferRoot();
        vm.stopPrank();
    }

    function testFuzz_transferRoot_RevertWhen_OwnerIsZero(bool proxy, address caller) public {
        vm.assume(caller != address(0));
        getRootOwner(proxy).initialize(address(0));
        assertEq(getRootOwner(proxy).root(), address(0));

        vm.startPrank(caller);
        vm.expectRevert(OnlyRoot.selector);
        getRootOwner(proxy).transferRoot();
        vm.stopPrank();
    }

    function testFuzz_transferRootOpen_when_ownerIsZero(bool proxy) public {
        getRootOwner(proxy).initialize(address(0));
        assertEq(getRootOwner(proxy).root(), address(0));

        vm.expectEmit();
        emit Transfer();
        getRootOwner(proxy).transferRootOpen();
    }

    function testFuzz_transferRootOpen_RevertWhen_owner(bool proxy) public {
        vm.expectRevert(OnlyRoot.selector);
        getRootOwner(proxy).transferRootOpen();
    }
}
