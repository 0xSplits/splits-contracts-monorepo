// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "./Base.t.sol";
import { MultiSignerMock } from "./mocks/MultiSignerMock.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { MultiSigner } from "src/utils/MultiSigner.sol";

contract MultiSignerTest is BaseTest {
    MultiSignerMock multiSigner;
    bytes[] signers;

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    PublicKey MIKE;

    error InvalidThreshold();
    error InvalidNumberOfSigners();
    error InvalidSignerBytesLength(bytes signer);
    error InvalidEthereumAddressOwner(bytes signer);
    error Unauthorized();
    error SignerAlreadyAdded(bytes signer);
    error SignerPresentAtIndex(uint8 index);

    function setUp() public override {
        super.setUp();

        MIKE = PublicKey({ x: 1, y: 2 });

        signers.push(abi.encode(ALICE.addr));
        signers.push(abi.encode(BOB.addr));
        signers.push(abi.encode(MIKE.x, MIKE.y));

        multiSigner = MultiSignerMock(LibClone.clone(address(new MultiSignerMock())));
    }

    function initializeSigners() internal {
        multiSigner.initialize(ALICE.addr, signers, 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 INITIALIZE                                 */
    /* -------------------------------------------------------------------------- */

    function test_initialize_signers() public {
        vm.expectEmit();
        emit MultiSigner.AddSigner(0, abi.encode(ALICE.addr));
        emit MultiSigner.AddSigner(1, abi.encode(BOB.addr));
        emit MultiSigner.AddSigner(2, abi.encode(MIKE.x, MIKE.y));
        initializeSigners();

        assertEq(multiSigner.getSignerAtIndex(0), abi.encode(ALICE.addr));
        assertEq(multiSigner.getSignerAtIndex(1), abi.encode(BOB.addr));
        assertEq(multiSigner.getSignerAtIndex(2), abi.encode(MIKE.x, MIKE.y));
        assertEq(multiSigner.getSignerCount(), 3);
        assertEq(multiSigner.getThreshold(), 1);
    }

    function test_initialize_signers_RevertWhen_thresholdIsZero() public {
        vm.expectRevert(InvalidThreshold.selector);
        multiSigner.initialize(ALICE.addr, signers, 0);
    }

    function test_initialize_signers_RevertWhen_signersGreaterThan() public {
        vm.expectRevert(InvalidNumberOfSigners.selector);
        multiSigner.initialize(ALICE.addr, new bytes[](256), 1);
    }

    function test_initialize_signers_RevertWhen_zeroSigners() public {
        vm.expectRevert(InvalidNumberOfSigners.selector);
        multiSigner.initialize(ALICE.addr, new bytes[](0), 1);
    }

    function test_initialize_signers_RevertWhen_thresholdIsGreaterThanSigners() public {
        vm.expectRevert(InvalidThreshold.selector);
        multiSigner.initialize(ALICE.addr, signers, 4);
    }

    function testFuzz_initialize_signers_RevertWhen_invalidSignerBytesLength(bytes memory signer) public {
        vm.assume(signer.length != 32 && signer.length != 64);
        signers[0] = signer;
        vm.expectRevert(abi.encodeWithSelector(InvalidSignerBytesLength.selector, signer));
        multiSigner.initialize(ALICE.addr, signers, 1);
    }

    function testFuzz_initialize_signers_RevertWhen_invalidEOA(uint256 signer) public {
        vm.assume(signer > type(uint160).max);
        signers[0] = abi.encode(signer);
        vm.expectRevert(abi.encodeWithSelector(InvalidEthereumAddressOwner.selector, abi.encode(signer)));
        multiSigner.initialize(ALICE.addr, signers, 1);
    }

    function test_initialize_signers_contract() public {
        signers[0] = abi.encode(address(this));
        multiSigner.initialize(ALICE.addr, signers, 1);

        assertEq(multiSigner.getSignerAtIndex(0), abi.encode(address(this)));
        assertEq(multiSigner.getSignerAtIndex(1), abi.encode(BOB.addr));
        assertEq(multiSigner.getSignerAtIndex(2), abi.encode(MIKE.x, MIKE.y));
        assertEq(multiSigner.getSignerCount(), 3);
        assertEq(multiSigner.getThreshold(), 1);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  THRESHOLD                                 */
    /* -------------------------------------------------------------------------- */

    function test_updateThreshold() public {
        initializeSigners();

        vm.startPrank(ALICE.addr);
        vm.expectEmit();
        emit MultiSigner.UpdateThreshold(2);
        multiSigner.updateThreshold(2);
        vm.stopPrank();

        assertEq(multiSigner.getThreshold(), 2);
    }

    function testFuzz_updateThreshold_RevertWhen_callerNotRoot(address _caller, uint8 _threshold) public {
        vm.assume(_caller != ALICE.addr);
        initializeSigners();

        vm.startPrank(_caller);
        vm.expectRevert(Unauthorized.selector);
        multiSigner.updateThreshold(_threshold);
        vm.stopPrank();
    }

    function testFuzz_updateThreshold_RevertWhen_thresholdGreaterThanNumberOfSigners(uint8 _threshold) public {
        vm.assume(_threshold > 3);
        initializeSigners();

        vm.startPrank(ALICE.addr);
        vm.expectRevert(InvalidThreshold.selector);
        multiSigner.updateThreshold(_threshold);
        vm.stopPrank();
    }

    function test_updateThreshold_RevertWhen_thresholdIsZero() public {
        initializeSigners();

        vm.startPrank(ALICE.addr);
        vm.expectRevert(InvalidThreshold.selector);
        multiSigner.updateThreshold(0);
        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*                                REMOVE SIGNER                               */
    /* -------------------------------------------------------------------------- */

    function test_removeSigner() public {
        initializeSigners();

        vm.startPrank(ALICE.addr);
        vm.expectEmit();
        emit MultiSigner.RemoveSigner(0, abi.encode(ALICE.addr));
        multiSigner.removeSigner(0);
        vm.stopPrank();

        assertEq(multiSigner.getSignerCount(), 2);
        assertEq(multiSigner.getSignerAtIndex(0).length, 0);
    }

    function testFuzz_removeSigner_RevertWhen_callerNotRoot(address _caller) public {
        vm.assume(_caller != ALICE.addr);
        initializeSigners();

        vm.startPrank(_caller);
        vm.expectRevert(Unauthorized.selector);
        multiSigner.removeSigner(0);
        vm.stopPrank();
    }

    function testFuzz_removeSigner_RevertWhen_thresholdGreaterThanNumberOfSigners() public {
        multiSigner.initialize(ALICE.addr, signers, 3);

        vm.startPrank(ALICE.addr);
        vm.expectRevert(InvalidThreshold.selector);
        multiSigner.removeSigner(0);
        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*                                 ADD SIGNER                                 */
    /* -------------------------------------------------------------------------- */

    function test_addSigner() public {
        initializeSigners();

        vm.startPrank(ALICE.addr);
        vm.expectEmit();
        emit MultiSigner.AddSigner(3, abi.encode(BOB.addr));
        multiSigner.addSigner(abi.encode(BOB.addr), 3);
        vm.stopPrank();

        assertEq(multiSigner.getSignerCount(), 4);
        assertEq(multiSigner.getSignerAtIndex(3), abi.encode(BOB.addr));
    }

    function testFuzz_addSigner_RevertWhen_callerNotRoot(bytes memory _signer, address _caller) public {
        vm.assume(_caller != ALICE.addr);
        initializeSigners();

        vm.startPrank(_caller);
        vm.expectRevert(Unauthorized.selector);
        multiSigner.addSigner(_signer, 0);
        vm.stopPrank();
    }

    function test_addSigner_replace() public {
        initializeSigners();

        vm.expectRevert();
        vm.startPrank(ALICE.addr);
        multiSigner.addSigner(abi.encode(DAN.addr), uint8(0));
        vm.stopPrank();
    }

    function testFuzz_addSigner_RevertWhen_invalidSignerBytesLength(bytes memory signer) public {
        initializeSigners();
        vm.assume(signer.length != 32 && signer.length != 64);

        vm.startPrank(ALICE.addr);
        vm.expectRevert(abi.encodeWithSelector(InvalidSignerBytesLength.selector, signer));
        multiSigner.addSigner(signer, 3);
        vm.stopPrank();
    }

    function testFuzz_addSigner_RevertWhen_invalidEOA(uint256 signer) public {
        initializeSigners();
        vm.assume(signer > type(uint160).max);

        vm.startPrank(ALICE.addr);
        vm.expectRevert(abi.encodeWithSelector(InvalidEthereumAddressOwner.selector, abi.encode(signer)));
        multiSigner.addSigner(abi.encode(signer), 3);
        vm.stopPrank();
    }

    function test_addSigner_contract() public {
        initializeSigners();

        vm.startPrank(ALICE.addr);
        multiSigner.addSigner(abi.encode((address(this))), 3);
        vm.stopPrank();

        assertEq(multiSigner.getSignerAtIndex(3), abi.encode((address(this))));
    }

    function test_addSigner_RevertWhen_MaxSignersReached() public {
        bytes[] memory signers_ = new bytes[](255);
        for (uint256 i; i < signers_.length; i++) {
            signers_[i] = abi.encode(address(uint160(i + 1)));
        }
        multiSigner.initialize(ALICE.addr, signers_, 1);

        vm.startPrank(ALICE.addr);
        vm.expectRevert();
        multiSigner.addSigner(abi.encode((address(this))), 3);
        vm.stopPrank();
    }
}
