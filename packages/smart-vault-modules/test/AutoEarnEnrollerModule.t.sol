// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";

import { IERC20 } from "src/interfaces/IERC20.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import { ISmartVaultFactory, Signer } from "test/interfaces/ISmartVaultFactory.sol";

import { AutoEarnEnrollerModule } from "src/AutoEarnEnrollerModule.sol";
import { AutoEarnModule } from "src/AutoEarnModule.sol";

/// @dev Not a SmartVault: claims to be owned by `owner_` and never reports a module as enabled.
contract FakeAccount {
    address immutable CLAIMED_OWNER;

    constructor(address owner_) {
        CLAIMED_OWNER = owner_;
    }

    function owner() external view returns (address) {
        return CLAIMED_OWNER;
    }

    function isModuleEnabled(address) external pure returns (bool) {
        return false;
    }

    function execute(Call calldata) external payable { }
}

contract AutoEarnEnrollerModuleTest is Test {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @dev Base USDC address.
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Base Splits Earn USDC vault address (fee wrapper over Steakhouse Prime USDC V2).
    address constant EARN_VAULT = 0x189A1a23F46321a196646314E6a078a404513C8F;

    /// @dev Deployed SmartVaultFactory on Base.
    ISmartVaultFactory constant FACTORY = ISmartVaultFactory(0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C);

    /// @dev Deployed AutoEarnModuleV2 on Base.
    address constant AUTO_EARN_MODULE_V2 = 0x4A5aCfc49597D1D326221cd159d42817918B9F5f;

    /// @dev Splits Labs workspace Treasury on Base.
    ISmartVault constant SPLITS_LABS_TREASURY = ISmartVault(0x99469Aa9C7B83F16349c77f5cc7B629fBc2617a1);

    /// @dev Splits Labs sub-account on Base, owned by `SPLITS_LABS_TREASURY`.
    ISmartVault constant SPLITS_LABS_SUB_ACCOUNT = ISmartVault(0x70C19d27fCfb8d434A4155973838B8572cE2AcFF);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error ZeroAddress();
    error AccountNotDeployed();
    error TreasuryNotDeployed();
    error NotOwnedByTreasury();
    error OnlyModule();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event Enrolled(address indexed treasury, address indexed account);

    /* -------------------------------------------------------------------------- */
    /*                                    STATE                                   */
    /* -------------------------------------------------------------------------- */

    AutoEarnModule autoEarnModule;
    AutoEarnEnrollerModule enroller;

    ISmartVault treasury;
    ISmartVault subAccount;

    address rootOwner;

    /* -------------------------------------------------------------------------- */
    /*                                    SETUP                                   */
    /* -------------------------------------------------------------------------- */

    function setUp() public {
        vm.createSelectFork("base");

        rootOwner = makeAddr("ROOT_OWNER");

        autoEarnModule = new AutoEarnModule(USDC, EARN_VAULT);
        enroller = new AutoEarnEnrollerModule(address(autoEarnModule));

        treasury = _createVault(rootOwner, 0);
        subAccount = _createVault(address(treasury), 1);

        _enableModule(treasury, address(enroller));
    }

    /* -------------------------------------------------------------------------- */
    /*                                   HELPERS                                  */
    /* -------------------------------------------------------------------------- */

    function _createVault(address owner_, uint256 salt_) internal returns (ISmartVault) {
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(rootOwner))), slot2: bytes32(0) });
        return ISmartVault(FACTORY.createAccount(owner_, signers, 1, salt_));
    }

    function _enableModule(ISmartVault vault_, address module_) internal {
        vm.prank(address(vault_));
        vault_.enableModule(module_);
    }

    function _disableModule(ISmartVault vault_, address module_) internal {
        vm.prank(address(vault_));
        vault_.disableModule(module_);
    }

    function _enableModuleCall(address account_) internal view returns (Call memory) {
        return
            Call({
                target: account_, value: 0, data: abi.encodeCall(ISmartVault.enableModule, (address(autoEarnModule)))
            });
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    function test_constructor() public view {
        assertEq(enroller.AUTO_EARN_MODULE(), address(autoEarnModule));
    }

    function testFuzz_constructor(address autoEarnModule_) public {
        vm.assume(autoEarnModule_ != address(0));
        AutoEarnEnrollerModule m = new AutoEarnEnrollerModule(autoEarnModule_);
        assertEq(m.AUTO_EARN_MODULE(), autoEarnModule_);
    }

    function test_constructor_RevertsWhen_zeroAddress() public {
        vm.expectRevert(ZeroAddress.selector);
        new AutoEarnEnrollerModule(address(0));
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ENROLL                                   */
    /* -------------------------------------------------------------------------- */

    function test_enroll_subAccount() public {
        assertFalse(subAccount.isModuleEnabled(address(autoEarnModule)));

        vm.expectEmit(true, true, false, true, address(enroller));
        emit Enrolled(address(treasury), address(subAccount));
        enroller.enroll(treasury, subAccount);

        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
        // Only the sub-account is enrolled.
        assertFalse(treasury.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_treasury() public {
        assertFalse(treasury.isModuleEnabled(address(autoEarnModule)));

        vm.expectEmit(true, true, false, true, address(enroller));
        emit Enrolled(address(treasury), address(treasury));
        enroller.enroll(treasury, treasury);

        assertTrue(treasury.isModuleEnabled(address(autoEarnModule)));
        // Only the Treasury is enrolled.
        assertFalse(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_subAccount_executesExpectedCalls() public {
        Call memory enableModuleCall = _enableModuleCall(address(subAccount));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(subAccount), value: 0, data: abi.encodeCall(ISmartVault.execute, (enableModuleCall))
        });

        // Treasury.executeFromModule -> subAccount.execute -> subAccount.enableModule.
        vm.expectCall(address(treasury), abi.encodeCall(ISmartVault.executeFromModule, (calls)), 1);
        vm.expectCall(address(subAccount), abi.encodeCall(ISmartVault.execute, (enableModuleCall)), 1);
        vm.expectCall(address(subAccount), enableModuleCall.data, 1);
        enroller.enroll(treasury, subAccount);
    }

    function test_enroll_treasury_executesExpectedCalls() public {
        Call[] memory calls = new Call[](1);
        calls[0] = _enableModuleCall(address(treasury));

        vm.expectCall(address(treasury), abi.encodeCall(ISmartVault.executeFromModule, (calls)), 1);
        vm.expectCall(address(treasury), calls[0].data, 1);
        enroller.enroll(treasury, treasury);
    }

    /// @dev Each run pranks a new address, which costs a fork RPC call, so runs are capped.
    /// forge-config: default.fuzz.runs = 16
    function testFuzz_enroll_callableByAnyone(address caller_) public {
        vm.prank(caller_);
        enroller.enroll(treasury, subAccount);

        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_multipleSubAccounts() public {
        ISmartVault subAccount2 = _createVault(address(treasury), 2);
        ISmartVault subAccount3 = _createVault(address(treasury), 3);

        enroller.enroll(treasury, subAccount);
        enroller.enroll(treasury, subAccount3);

        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
        assertTrue(subAccount3.isModuleEnabled(address(autoEarnModule)));
        // Sub-accounts are enrolled independently.
        assertFalse(subAccount2.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_subAccount_thenDeposit() public {
        // The earn vault uses Cancun opcodes; the package targets Shanghai.
        vm.setEvmVersion("cancun");

        enroller.enroll(treasury, subAccount);

        uint256 amount = 1000e6; // 1,000 USDC
        deal(USDC, address(subAccount), amount);

        autoEarnModule.deposit(subAccount);

        // USDC swept into the earn vault.
        assertEq(IERC20(USDC).balanceOf(address(subAccount)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(subAccount)), 0);
    }

    function test_enroll_subAccount_reEnablesAfterAccountDisables() public {
        enroller.enroll(treasury, subAccount);
        _disableModule(subAccount, address(autoEarnModule));

        // By design, an account can't opt out on its own while the enroller is enabled on its Treasury.
        vm.expectEmit(true, true, false, true, address(enroller));
        emit Enrolled(address(treasury), address(subAccount));
        vm.prank(makeAddr("ANYONE"));
        enroller.enroll(treasury, subAccount);

        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    /* -------------------------------------------------------------------------- */
    /*                                   NO-OPS                                   */
    /* -------------------------------------------------------------------------- */

    function test_enroll_subAccount_noOp_whenAlreadyEnabled() public {
        _enableModule(subAccount, address(autoEarnModule));

        vm.recordLogs();
        vm.expectCall(address(treasury), abi.encodeWithSelector(ISmartVault.executeFromModule.selector), 0);
        enroller.enroll(treasury, subAccount);

        // Nothing executed and nothing emitted (no `Enrolled`, `ExecutedTxFromModule` or `EnabledModule`).
        assertEq(vm.getRecordedLogs().length, 0);
        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_treasury_noOp_whenAlreadyEnabled() public {
        _enableModule(treasury, address(autoEarnModule));

        vm.recordLogs();
        vm.expectCall(address(treasury), abi.encodeWithSelector(ISmartVault.executeFromModule.selector), 0);
        enroller.enroll(treasury, treasury);

        // Nothing executed and nothing emitted (no `Enrolled`, `ExecutedTxFromModule` or `EnabledModule`).
        assertEq(vm.getRecordedLogs().length, 0);
        assertTrue(treasury.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_noOp_whenCalledTwice() public {
        enroller.enroll(treasury, subAccount);

        vm.recordLogs();
        vm.expectCall(address(treasury), abi.encodeWithSelector(ISmartVault.executeFromModule.selector), 0);
        enroller.enroll(treasury, subAccount);

        // Nothing executed and nothing emitted (no `Enrolled`, `ExecutedTxFromModule` or `EnabledModule`).
        assertEq(vm.getRecordedLogs().length, 0);
        assertTrue(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_noOp_whenAlreadyEnabled_evenIfEnrollerNotEnabled() public {
        ISmartVault otherTreasury = _createVault(rootOwner, 50);
        ISmartVault otherSubAccount = _createVault(address(otherTreasury), 51);
        _enableModule(otherTreasury, address(autoEarnModule));
        _enableModule(otherSubAccount, address(autoEarnModule));

        // The no-op returns before calling the Treasury, so `onlyModule` is never reached.
        enroller.enroll(otherTreasury, otherSubAccount);
        enroller.enroll(otherTreasury, otherTreasury);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   REVERTS                                  */
    /* -------------------------------------------------------------------------- */

    function test_enroll_RevertsWhen_accountNotDeployed() public {
        address undeployed = makeAddr("UNDEPLOYED");

        vm.expectRevert(AccountNotDeployed.selector);
        enroller.enroll(treasury, ISmartVault(undeployed));
    }

    function test_enroll_RevertsWhen_treasuryNotDeployed() public {
        // A sub-account can be deployed on a chain before its Treasury is.
        address undeployedTreasury = makeAddr("UNDEPLOYED_TREASURY");
        ISmartVault orphanSubAccount = _createVault(undeployedTreasury, 60);

        vm.expectRevert(TreasuryNotDeployed.selector);
        enroller.enroll(ISmartVault(undeployedTreasury), orphanSubAccount);

        // An ownerless vault would pass the owner check for `treasury_ == address(0)`; the code check stops it first.
        ISmartVault ownerlessAccount = _createVault(address(0), 61);

        vm.expectRevert(TreasuryNotDeployed.selector);
        enroller.enroll(ISmartVault(address(0)), ownerlessAccount);
    }

    function test_enroll_RevertsWhen_treasuryNotDeployed_evenIfAlreadyEnabled() public {
        address undeployedTreasury = makeAddr("UNDEPLOYED_TREASURY");
        ISmartVault orphanSubAccount = _createVault(undeployedTreasury, 62);
        _enableModule(orphanSubAccount, address(autoEarnModule));

        // The Treasury code check runs before the no-op check.
        vm.expectRevert(TreasuryNotDeployed.selector);
        enroller.enroll(ISmartVault(undeployedTreasury), orphanSubAccount);
    }

    function test_enroll_RevertsWhen_notOwnedByTreasury() public {
        ISmartVault otherAccount = _createVault(rootOwner, 10);

        vm.expectRevert(NotOwnedByTreasury.selector);
        enroller.enroll(treasury, otherAccount);

        assertFalse(otherAccount.isModuleEnabled(address(autoEarnModule)));
    }

    /// @dev Each run creates a vault at a new address, which costs a fork RPC call, so runs are capped.
    /// forge-config: default.fuzz.runs = 16
    function testFuzz_enroll_RevertsWhen_notOwnedByTreasury(address owner_) public {
        vm.assume(owner_ != address(treasury));
        ISmartVault otherAccount = _createVault(owner_, 11);

        vm.expectRevert(NotOwnedByTreasury.selector);
        enroller.enroll(treasury, otherAccount);
    }

    function test_enroll_RevertsWhen_notOwnedByTreasury_evenIfAlreadyEnabled() public {
        ISmartVault otherAccount = _createVault(rootOwner, 12);
        _enableModule(otherAccount, address(autoEarnModule));

        // The ownership check runs before the no-op check.
        vm.expectRevert(NotOwnedByTreasury.selector);
        enroller.enroll(treasury, otherAccount);
    }

    function test_enroll_RevertsWhen_ownedByOtherTreasury() public {
        // A second workspace that has also enabled the enroller.
        ISmartVault otherTreasury = _createVault(rootOwner, 20);
        ISmartVault otherSubAccount = _createVault(address(otherTreasury), 21);
        _enableModule(otherTreasury, address(enroller));

        // Treasury cannot enroll another workspace's sub-account.
        vm.expectRevert(NotOwnedByTreasury.selector);
        enroller.enroll(treasury, otherSubAccount);

        // The owning Treasury can.
        enroller.enroll(otherTreasury, otherSubAccount);
        assertTrue(otherSubAccount.isModuleEnabled(address(autoEarnModule)));
    }

    function test_enroll_RevertsWhen_treasuryIsSignerButNotOwner() public {
        // Treasury is the sole signer, but not the owner.
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(address(treasury)))), slot2: bytes32(0) });
        ISmartVault treasurySignedAccount = ISmartVault(FACTORY.createAccount(rootOwner, signers, 1, 30));

        vm.expectRevert(NotOwnedByTreasury.selector);
        enroller.enroll(treasury, treasurySignedAccount);
    }

    function test_enroll_RevertsWhen_enrollerNotEnabled() public {
        ISmartVault otherTreasury = _createVault(rootOwner, 40);
        ISmartVault otherSubAccount = _createVault(address(otherTreasury), 41);

        vm.expectRevert(OnlyModule.selector);
        enroller.enroll(otherTreasury, otherSubAccount);

        vm.expectRevert(OnlyModule.selector);
        enroller.enroll(otherTreasury, otherTreasury);
    }

    function test_enroll_RevertsWhen_enrollerDisabled() public {
        _disableModule(treasury, address(enroller));

        vm.expectRevert(OnlyModule.selector);
        enroller.enroll(treasury, subAccount);

        assertFalse(subAccount.isModuleEnabled(address(autoEarnModule)));
    }

    /* -------------------------------------------------------------------------- */
    /*                               FAKE ACCOUNTS                                */
    /* -------------------------------------------------------------------------- */

    function test_enroll_fakeAccount_onlyReceivesFixedCall() public {
        FakeAccount fake = new FakeAccount(address(treasury));
        Call memory enableModuleCall = _enableModuleCall(address(fake));
        // Fund the Treasury so that any value sent out would show in its balance.
        vm.deal(address(treasury), 1 ether);

        // `fake` receives one zero-value `execute` call with fixed calldata.
        vm.expectCall(address(fake), 0, abi.encodeCall(ISmartVault.execute, (enableModuleCall)), 1);
        // `Enrolled` is still emitted, although nothing was enabled.
        vm.expectEmit(true, true, false, true, address(enroller));
        emit Enrolled(address(treasury), address(fake));
        vm.prank(makeAddr("ANYONE"));
        enroller.enroll(treasury, ISmartVault(address(fake)));

        // The Treasury's ETH balance is unchanged, and the Treasury itself is not enrolled.
        assertEq(address(treasury).balance, 1 ether);
        assertFalse(treasury.isModuleEnabled(address(autoEarnModule)));
    }

    /* -------------------------------------------------------------------------- */
    /*                              LIVE WORKSPACE                                */
    /* -------------------------------------------------------------------------- */

    function test_enroll_splitsLabsWorkspace() public {
        // Sub-accounts created by the app are owned by the workspace Treasury.
        assertEq(SPLITS_LABS_SUB_ACCOUNT.owner(), address(SPLITS_LABS_TREASURY));

        AutoEarnEnrollerModule liveEnroller = new AutoEarnEnrollerModule(AUTO_EARN_MODULE_V2);
        _enableModule(SPLITS_LABS_TREASURY, address(liveEnroller));

        // Start both accounts without the auto earn module.
        if (SPLITS_LABS_TREASURY.isModuleEnabled(AUTO_EARN_MODULE_V2)) {
            _disableModule(SPLITS_LABS_TREASURY, AUTO_EARN_MODULE_V2);
        }
        if (SPLITS_LABS_SUB_ACCOUNT.isModuleEnabled(AUTO_EARN_MODULE_V2)) {
            _disableModule(SPLITS_LABS_SUB_ACCOUNT, AUTO_EARN_MODULE_V2);
        }

        liveEnroller.enroll(SPLITS_LABS_TREASURY, SPLITS_LABS_TREASURY);
        liveEnroller.enroll(SPLITS_LABS_TREASURY, SPLITS_LABS_SUB_ACCOUNT);

        assertTrue(SPLITS_LABS_TREASURY.isModuleEnabled(AUTO_EARN_MODULE_V2));
        assertTrue(SPLITS_LABS_SUB_ACCOUNT.isModuleEnabled(AUTO_EARN_MODULE_V2));
    }
}
