// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";

import { IERC20 } from "src/interfaces/IERC20.sol";
import { IERC4626 } from "src/interfaces/IERC4626.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import { ISmartVaultFactory, Signer } from "test/interfaces/ISmartVaultFactory.sol";

import { AutoEarnModule } from "src/AutoEarnModule.sol";
import { AutoEarnModuleMainnetUSDT } from "src/AutoEarnModuleMainnetUSDT.sol";

contract AutoEarnModuleMainnetUSDTTest is Test {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @dev Mainnet USDT address.
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    /// @dev Mainnet Splits Earn USDT vault address (fee wrapper over Steakhouse Prime USDT).
    address constant EARN_VAULT = 0xb5aeE31903Eb465DeF0ad08fE4A88D77D58100Db;

    /// @dev Deployed SmartVaultFactory on mainnet.
    ISmartVaultFactory constant FACTORY = ISmartVaultFactory(0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C);

    /// @dev Splits Labs workspace Treasury on mainnet.
    ISmartVault constant SPLITS_LABS_TREASURY = ISmartVault(0x99469Aa9C7B83F16349c77f5cc7B629fBc2617a1);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error ZeroAddress();
    error OnlyModule();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event Deposited(address indexed account, uint256 amount);

    /* -------------------------------------------------------------------------- */
    /*                                    STATE                                   */
    /* -------------------------------------------------------------------------- */

    ISmartVault vault;
    AutoEarnModuleMainnetUSDT module;

    address owner;
    uint256 ownerKey;

    /* -------------------------------------------------------------------------- */
    /*                                    SETUP                                   */
    /* -------------------------------------------------------------------------- */

    function setUp() public {
        vm.createSelectFork("mainnet");
        // The earn vault uses Cancun opcodes; the package targets Shanghai.
        vm.setEvmVersion("cancun");

        (owner, ownerKey) = makeAddrAndKey("OWNER");

        module = new AutoEarnModuleMainnetUSDT(USDT, EARN_VAULT);

        vault = _createVaultWithModule(0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   HELPERS                                  */
    /* -------------------------------------------------------------------------- */

    function _createVaultWithModule(uint256 salt_) internal returns (ISmartVault) {
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault v = ISmartVault(FACTORY.createAccount(owner, signers, 1, salt_));
        vm.prank(address(v));
        v.enableModule(address(module));
        return v;
    }

    /// @dev USDT's `approve` returns no value, so the `IERC20` interface can't decode its result.
    function _approveUsdt(ISmartVault account_, uint256 amount_) internal {
        vm.prank(address(account_));
        (bool success,) = USDT.call(abi.encodeCall(IERC20.approve, (EARN_VAULT, amount_)));
        assertTrue(success);
        assertEq(IERC20(USDT).allowance(address(account_), EARN_VAULT), amount_);
    }

    /// @dev Enables the module on the Splits Labs Treasury and returns its USDT balance. If the Treasury no longer
    ///      holds USDT, it is topped up so that these tests still sweep a nonzero balance.
    function _setUpSplitsLabsTreasury() internal returns (uint256 balance) {
        vm.prank(address(SPLITS_LABS_TREASURY));
        SPLITS_LABS_TREASURY.enableModule(address(module));

        balance = IERC20(USDT).balanceOf(address(SPLITS_LABS_TREASURY));
        if (balance == 0) {
            balance = 1000e6;
            deal(USDT, address(SPLITS_LABS_TREASURY), balance);
        }
    }

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    function test_constructor() public view {
        assertEq(module.ASSET(), USDT);
        assertEq(module.VAULT(), EARN_VAULT);
    }

    function testFuzz_constructor(address asset_, address vault_) public {
        vm.assume(asset_ != address(0) && vault_ != address(0));
        AutoEarnModuleMainnetUSDT m = new AutoEarnModuleMainnetUSDT(asset_, vault_);
        assertEq(m.ASSET(), asset_);
        assertEq(m.VAULT(), vault_);
    }

    function test_constructor_RevertsWhen_zeroUsdt() public {
        vm.expectRevert(ZeroAddress.selector);
        new AutoEarnModuleMainnetUSDT(address(0), EARN_VAULT);
    }

    function test_constructor_RevertsWhen_zeroVault() public {
        vm.expectRevert(ZeroAddress.selector);
        new AutoEarnModuleMainnetUSDT(USDT, address(0));
    }

    function test_constructor_RevertsWhen_bothZero() public {
        vm.expectRevert(ZeroAddress.selector);
        new AutoEarnModuleMainnetUSDT(address(0), address(0));
    }

    /* -------------------------------------------------------------------------- */
    /*                                   DEPOSIT                                  */
    /* -------------------------------------------------------------------------- */

    function test_deposit() public {
        uint256 amount = 1000e6; // 1,000 USDT
        deal(USDT, address(vault), amount);

        assertEq(IERC20(USDT).balanceOf(address(vault)), amount);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        vm.expectEmit(true, false, false, true, address(module));
        emit Deposited(address(vault), amount);
        module.deposit(vault);

        // USDT should be fully swept from the vault.
        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        // Vault should have received earn vault shares.
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        // Module should never hold USDT.
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        // Approval should be fully consumed.
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function test_deposit_executesExpectedCalls() public {
        uint256 amount = 1000e6;
        deal(USDT, address(vault), amount);

        Call[] memory calls = new Call[](3);
        calls[0] = Call({ target: USDT, value: 0, data: abi.encodeCall(IERC20.approve, (EARN_VAULT, 0)) });
        calls[1] = Call({ target: USDT, value: 0, data: abi.encodeCall(IERC20.approve, (EARN_VAULT, amount)) });
        calls[2] =
            Call({ target: EARN_VAULT, value: 0, data: abi.encodeCall(IERC4626.deposit, (amount, address(vault))) });

        // Vault.executeFromModule -> USDT.approve(0) -> USDT.approve(amount) -> EARN_VAULT.deposit.
        vm.expectCall(address(vault), abi.encodeCall(ISmartVault.executeFromModule, (calls)), 1);
        vm.expectCall(USDT, calls[0].data, 1);
        vm.expectCall(USDT, calls[1].data, 1);
        vm.expectCall(EARN_VAULT, calls[2].data, 1);
        module.deposit(vault);
    }

    function testFuzz_deposit(uint256 amount_) public {
        // Bound to reasonable USDT amounts (1 USDT to 100M USDT).
        amount_ = bound(amount_, 1e6, 100_000_000e6);

        deal(USDT, address(vault), amount_);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        // Approval should be fully consumed.
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function test_deposit_noOp_whenNoBalance() public {
        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);

        // Should return silently (no-op) instead of reverting.
        module.deposit(vault);

        // State unchanged.
        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault)), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                            EXISTING APPROVAL                              */
    /* -------------------------------------------------------------------------- */

    function test_deposit_withExistingApprovalGreaterThanBalance() public {
        uint256 amount = 1000e6;
        deal(USDT, address(vault), amount);

        // Set a pre-existing approval larger than balance.
        _approveUsdt(vault, 5000e6);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        // Approval is reset to zero, set to `amount` by the module, then fully consumed by the vault deposit.
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function test_deposit_withExistingApprovalLessThanBalance() public {
        uint256 amount = 1000e6;
        deal(USDT, address(vault), amount);

        // Set a pre-existing approval smaller than balance.
        _approveUsdt(vault, 500e6);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        // Approval is reset to zero, set to `amount` by the module, then fully consumed by the vault deposit.
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function test_deposit_withExistingApprovalEqualToBalance() public {
        uint256 amount = 1000e6;
        deal(USDT, address(vault), amount);

        // Set a pre-existing approval equal to balance.
        _approveUsdt(vault, amount);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        // Approval fully consumed by the vault deposit.
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function testFuzz_deposit_withExistingApproval(uint256 amount_, uint256 allowance_) public {
        amount_ = bound(amount_, 1e6, 100_000_000e6);
        allowance_ = bound(allowance_, 1, type(uint256).max);

        deal(USDT, address(vault), amount_);
        _approveUsdt(vault, allowance_);

        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    function test_autoEarnModule_deposit_RevertsWhen_existingApproval() public {
        // The unchanged AutoEarnModule approves without resetting first, which USDT rejects.
        AutoEarnModule autoEarnModule = new AutoEarnModule(USDT, EARN_VAULT);
        vm.prank(address(vault));
        vault.enableModule(address(autoEarnModule));

        deal(USDT, address(vault), 1000e6);
        _approveUsdt(vault, 1);

        // USDT's `approve` reverts without data, and the SmartVault bubbles it up.
        vm.expectRevert(bytes(""), USDT);
        autoEarnModule.deposit(vault);

        // This module sweeps the same account.
        module.deposit(vault);

        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(vault)), 0);
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   REVERTS                                  */
    /* -------------------------------------------------------------------------- */

    function test_deposit_RevertsWhen_moduleNotEnabled() public {
        // Create a second vault without the module enabled.
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault vault2 = ISmartVault(FACTORY.createAccount(owner, signers, 1, 1));

        deal(USDT, address(vault2), 1000e6);

        vm.expectRevert(OnlyModule.selector);
        module.deposit(vault2);
    }

    function test_deposit_multipleDeposits() public {
        // First deposit.
        deal(USDT, address(vault), 500e6);
        module.deposit(vault);

        uint256 sharesAfterFirst = IERC20(EARN_VAULT).balanceOf(address(vault));
        assertGt(sharesAfterFirst, 0);
        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);

        // Second deposit.
        deal(USDT, address(vault), 1000e6);
        module.deposit(vault);

        uint256 sharesAfterSecond = IERC20(EARN_VAULT).balanceOf(address(vault));
        assertGt(sharesAfterSecond, sharesAfterFirst);
        assertEq(IERC20(USDT).balanceOf(address(vault)), 0);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(vault), EARN_VAULT), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 MULTI-VAULT                                */
    /* -------------------------------------------------------------------------- */

    function test_deposit_multipleVaults() public {
        ISmartVault vault1 = _createVaultWithModule(10);
        ISmartVault vault2 = _createVaultWithModule(11);
        ISmartVault vault3 = _createVaultWithModule(12);

        deal(USDT, address(vault1), 500e6);
        deal(USDT, address(vault2), 1000e6);
        deal(USDT, address(vault3), 2000e6);

        // --- Deposit vault1 ---
        module.deposit(vault1);

        uint256 shares1 = IERC20(EARN_VAULT).balanceOf(address(vault1));
        assertEq(IERC20(USDT).balanceOf(address(vault1)), 0);
        assertGt(shares1, 0);
        // Other vaults untouched.
        assertEq(IERC20(USDT).balanceOf(address(vault2)), 1000e6);
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 2000e6);
        // Module holds nothing.
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);

        // --- Deposit vault2 ---
        module.deposit(vault2);

        uint256 shares2 = IERC20(EARN_VAULT).balanceOf(address(vault2));
        assertEq(IERC20(USDT).balanceOf(address(vault2)), 0);
        assertGt(shares2, 0);
        // vault1 shares unchanged, vault3 still untouched.
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 2000e6);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);

        // --- Deposit vault3 ---
        module.deposit(vault3);

        uint256 shares3 = IERC20(EARN_VAULT).balanceOf(address(vault3));
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 0);
        assertGt(shares3, 0);
        // vault1 and vault2 shares unchanged.
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault2)), shares2);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
    }

    function test_deposit_RevertsWhen_moduleDisabled() public {
        ISmartVault v = _createVaultWithModule(30);
        deal(USDT, address(v), 1000e6);

        // Deposit succeeds while module is enabled.
        module.deposit(v);

        uint256 shares = IERC20(EARN_VAULT).balanceOf(address(v));
        assertEq(IERC20(USDT).balanceOf(address(v)), 0);
        assertGt(shares, 0);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);

        // Disable the module.
        vm.prank(address(v));
        v.disableModule(address(module));

        // Fund the vault again.
        deal(USDT, address(v), 500e6);

        // Deposit reverts now that the module is disabled.
        vm.expectRevert(OnlyModule.selector);
        module.deposit(v);

        // USDT remains in the vault, untouched.
        assertEq(IERC20(USDT).balanceOf(address(v)), 500e6);
        // Shares from the first deposit are still there.
        assertEq(IERC20(EARN_VAULT).balanceOf(address(v)), shares);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
    }

    function test_deposit_multipleVaults_independentFailures() public {
        ISmartVault vault1 = _createVaultWithModule(20);
        ISmartVault vault2 = _createVaultWithModule(21);

        // vault3 does NOT have the module enabled.
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault vault3 = ISmartVault(FACTORY.createAccount(owner, signers, 1, 22));

        deal(USDT, address(vault1), 500e6);
        deal(USDT, address(vault2), 1000e6);
        deal(USDT, address(vault3), 1500e6);

        // --- Deposit vault1 succeeds ---
        module.deposit(vault1);

        uint256 shares1 = IERC20(EARN_VAULT).balanceOf(address(vault1));
        assertEq(IERC20(USDT).balanceOf(address(vault1)), 0);
        assertGt(shares1, 0);
        assertEq(IERC20(USDT).balanceOf(address(vault2)), 1000e6);
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);

        // --- Deposit vault3 reverts (module not enabled) ---
        vm.expectRevert(OnlyModule.selector);
        module.deposit(vault3);

        // vault3 USDT unchanged, vault1 shares unchanged.
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);

        // --- Deposit vault2 still succeeds ---
        module.deposit(vault2);

        uint256 shares2 = IERC20(EARN_VAULT).balanceOf(address(vault2));
        assertEq(IERC20(USDT).balanceOf(address(vault2)), 0);
        assertGt(shares2, 0);
        // vault1 shares unchanged, vault3 USDT still untouched.
        assertEq(IERC20(EARN_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDT).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                LIVE ACCOUNT                                */
    /* -------------------------------------------------------------------------- */

    function test_deposit_splitsLabsTreasury() public {
        uint256 amount = _setUpSplitsLabsTreasury();
        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY));

        vm.expectEmit(true, false, false, true, address(module));
        emit Deposited(address(SPLITS_LABS_TREASURY), amount);
        module.deposit(SPLITS_LABS_TREASURY);

        assertEq(IERC20(USDT).balanceOf(address(SPLITS_LABS_TREASURY)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(SPLITS_LABS_TREASURY), EARN_VAULT), 0);
    }

    function test_deposit_splitsLabsTreasury_twice() public {
        _setUpSplitsLabsTreasury();

        // First sweep.
        module.deposit(SPLITS_LABS_TREASURY);

        uint256 sharesAfterFirst = IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY));
        assertEq(IERC20(USDT).balanceOf(address(SPLITS_LABS_TREASURY)), 0);
        assertEq(IERC20(USDT).allowance(address(SPLITS_LABS_TREASURY), EARN_VAULT), 0);

        // More USDT arrives, and the second sweep starts from the zero allowance the first one left.
        deal(USDT, address(SPLITS_LABS_TREASURY), 1000e6);
        module.deposit(SPLITS_LABS_TREASURY);

        assertEq(IERC20(USDT).balanceOf(address(SPLITS_LABS_TREASURY)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY)), sharesAfterFirst);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(SPLITS_LABS_TREASURY), EARN_VAULT), 0);
    }

    function test_deposit_splitsLabsTreasury_withExistingApproval() public {
        uint256 amount = _setUpSplitsLabsTreasury();
        uint256 sharesBefore = IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY));

        // A leftover allowance, e.g. from a manual deposit that approved more than it deposited.
        _approveUsdt(SPLITS_LABS_TREASURY, 1);

        vm.expectEmit(true, false, false, true, address(module));
        emit Deposited(address(SPLITS_LABS_TREASURY), amount);
        module.deposit(SPLITS_LABS_TREASURY);

        assertEq(IERC20(USDT).balanceOf(address(SPLITS_LABS_TREASURY)), 0);
        assertGt(IERC20(EARN_VAULT).balanceOf(address(SPLITS_LABS_TREASURY)), sharesBefore);
        assertEq(IERC20(USDT).balanceOf(address(module)), 0);
        assertEq(IERC20(USDT).allowance(address(SPLITS_LABS_TREASURY), EARN_VAULT), 0);
    }
}
