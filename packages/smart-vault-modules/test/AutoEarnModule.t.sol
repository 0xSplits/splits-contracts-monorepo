// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";

import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import { ISmartVaultFactory, Signer } from "test/interfaces/ISmartVaultFactory.sol";

import { AutoEarnModule } from "src/AutoEarnModule.sol";

contract AutoEarnModuleTest is Test {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /// @dev Base USDC address.
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    /// @dev Base Aave USDC earn vault address.
    address constant AAVE_VAULT = 0x4EA71A20e655794051D1eE8b6e4A3269B13ccaCc;

    /// @dev Deployed SmartVaultFactory on Base.
    ISmartVaultFactory constant FACTORY = ISmartVaultFactory(0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error NoBalance();
    error OnlyModule();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event ExecutedTxFromModule(address indexed module, Call call);

    /* -------------------------------------------------------------------------- */
    /*                                    STATE                                   */
    /* -------------------------------------------------------------------------- */

    ISmartVault vault;
    AutoEarnModule module;

    address owner;
    uint256 ownerKey;

    /* -------------------------------------------------------------------------- */
    /*                                    SETUP                                   */
    /* -------------------------------------------------------------------------- */

    function setUp() public {
        vm.createSelectFork("base");

        (owner, ownerKey) = makeAddrAndKey("OWNER");

        module = new AutoEarnModule(USDC, AAVE_VAULT);

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

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    function test_constructor() public view {
        assertEq(module.USDC(), USDC);
        assertEq(module.VAULT(), AAVE_VAULT);
    }

    function testFuzz_constructor(address usdc_, address vault_) public {
        AutoEarnModule m = new AutoEarnModule(usdc_, vault_);
        assertEq(m.USDC(), usdc_);
        assertEq(m.VAULT(), vault_);
    }

    /* -------------------------------------------------------------------------- */
    /*                                   DEPOSIT                                  */
    /* -------------------------------------------------------------------------- */

    function test_deposit() public {
        uint256 amount = 1000e6; // 1,000 USDC
        deal(USDC, address(vault), amount);

        assertEq(IERC20(USDC).balanceOf(address(vault)), amount);

        uint256 sharesBefore = IERC20(AAVE_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        // USDC should be fully swept from the vault.
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
        // Vault should have received aToken shares.
        assertGt(IERC20(AAVE_VAULT).balanceOf(address(vault)), sharesBefore);
        // Module should never hold USDC.
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);
    }

    function testFuzz_deposit(uint256 amount_) public {
        // Bound to reasonable USDC amounts (1 USDC to 100M USDC).
        // Aave's pool reverts with INVALID_AMOUNT for sub-unit deposits.
        amount_ = bound(amount_, 1e6, 100_000_000e6);

        deal(USDC, address(vault), amount_);

        uint256 sharesBefore = IERC20(AAVE_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
        assertGt(IERC20(AAVE_VAULT).balanceOf(address(vault)), sharesBefore);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);
    }

    function test_deposit_RevertsWhen_noBalance() public {
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);

        vm.expectRevert(NoBalance.selector);
        module.deposit(vault);
    }

    function test_deposit_RevertsWhen_moduleNotEnabled() public {
        // Create a second vault without the module enabled.
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault vault2 = ISmartVault(FACTORY.createAccount(owner, signers, 1, 1));

        deal(USDC, address(vault2), 1000e6);

        vm.expectRevert(OnlyModule.selector);
        module.deposit(vault2);
    }

    function test_deposit_multipleDeposits() public {
        // First deposit.
        deal(USDC, address(vault), 500e6);
        module.deposit(vault);

        uint256 sharesAfterFirst = IERC20(AAVE_VAULT).balanceOf(address(vault));
        assertGt(sharesAfterFirst, 0);
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);

        // Second deposit.
        deal(USDC, address(vault), 1000e6);
        module.deposit(vault);

        uint256 sharesAfterSecond = IERC20(AAVE_VAULT).balanceOf(address(vault));
        assertGt(sharesAfterSecond, sharesAfterFirst);
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                                 MULTI-VAULT                                */
    /* -------------------------------------------------------------------------- */

    function test_deposit_multipleVaults() public {
        ISmartVault vault1 = _createVaultWithModule(10);
        ISmartVault vault2 = _createVaultWithModule(11);
        ISmartVault vault3 = _createVaultWithModule(12);

        deal(USDC, address(vault1), 500e6);
        deal(USDC, address(vault2), 1000e6);
        deal(USDC, address(vault3), 2000e6);

        // --- Deposit vault1 ---
        module.deposit(vault1);

        uint256 shares1 = IERC20(AAVE_VAULT).balanceOf(address(vault1));
        assertEq(IERC20(USDC).balanceOf(address(vault1)), 0);
        assertGt(shares1, 0);
        // Other vaults untouched.
        assertEq(IERC20(USDC).balanceOf(address(vault2)), 1000e6);
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 2000e6);
        // Module holds nothing.
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);

        // --- Deposit vault2 ---
        module.deposit(vault2);

        uint256 shares2 = IERC20(AAVE_VAULT).balanceOf(address(vault2));
        assertEq(IERC20(USDC).balanceOf(address(vault2)), 0);
        assertGt(shares2, 0);
        // vault1 shares unchanged, vault3 still untouched.
        assertEq(IERC20(AAVE_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 2000e6);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);

        // --- Deposit vault3 ---
        module.deposit(vault3);

        uint256 shares3 = IERC20(AAVE_VAULT).balanceOf(address(vault3));
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 0);
        assertGt(shares3, 0);
        // vault1 and vault2 shares unchanged.
        assertEq(IERC20(AAVE_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(AAVE_VAULT).balanceOf(address(vault2)), shares2);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);
    }

    function test_deposit_multipleVaults_independentFailures() public {
        ISmartVault vault1 = _createVaultWithModule(20);
        ISmartVault vault2 = _createVaultWithModule(21);

        // vault3 does NOT have the module enabled.
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });
        ISmartVault vault3 = ISmartVault(FACTORY.createAccount(owner, signers, 1, 22));

        deal(USDC, address(vault1), 500e6);
        deal(USDC, address(vault2), 1000e6);
        deal(USDC, address(vault3), 1500e6);

        // --- Deposit vault1 succeeds ---
        module.deposit(vault1);

        uint256 shares1 = IERC20(AAVE_VAULT).balanceOf(address(vault1));
        assertEq(IERC20(USDC).balanceOf(address(vault1)), 0);
        assertGt(shares1, 0);
        assertEq(IERC20(USDC).balanceOf(address(vault2)), 1000e6);
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);

        // --- Deposit vault3 reverts (module not enabled) ---
        vm.expectRevert(OnlyModule.selector);
        module.deposit(vault3);

        // vault3 USDC unchanged, vault1 shares unchanged.
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(AAVE_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);

        // --- Deposit vault2 still succeeds ---
        module.deposit(vault2);

        uint256 shares2 = IERC20(AAVE_VAULT).balanceOf(address(vault2));
        assertEq(IERC20(USDC).balanceOf(address(vault2)), 0);
        assertGt(shares2, 0);
        // vault1 shares unchanged, vault3 USDC still untouched.
        assertEq(IERC20(AAVE_VAULT).balanceOf(address(vault1)), shares1);
        assertEq(IERC20(USDC).balanceOf(address(vault3)), 1500e6);
        assertEq(IERC20(USDC).balanceOf(address(module)), 0);
    }
}
