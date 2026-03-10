// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";

import { IERC20 } from "forge-std/interfaces/IERC20.sol";
import { Call, ISmartVault } from "src/interfaces/ISmartVault.sol";
import { ISmartVaultFactory, Signer } from "src/interfaces/ISmartVaultFactory.sol";

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

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ slot1: bytes32(uint256(uint160(owner))), slot2: bytes32(0) });

        address account = FACTORY.createAccount(owner, signers, 1, 0);
        vault = ISmartVault(account);

        module = new AutoEarnModule(USDC, AAVE_VAULT);

        // Enable the module on the vault (requires self-call).
        vm.prank(address(vault));
        vault.enableModule(address(module));
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

        // Get vault's aToken balance before deposit.
        uint256 sharesBefore = IERC20(AAVE_VAULT).balanceOf(address(vault));

        module.deposit(vault);

        // USDC should be fully swept from the vault.
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);

        // Vault should have received aToken shares.
        uint256 sharesAfter = IERC20(AAVE_VAULT).balanceOf(address(vault));
        assertGt(sharesAfter, sharesBefore);
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

        // Second deposit.
        deal(USDC, address(vault), 1000e6);
        module.deposit(vault);

        uint256 sharesAfterSecond = IERC20(AAVE_VAULT).balanceOf(address(vault));
        assertGt(sharesAfterSecond, sharesAfterFirst);
        assertEq(IERC20(USDC).balanceOf(address(vault)), 0);
    }
}
