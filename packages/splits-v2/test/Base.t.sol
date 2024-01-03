// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Warehouse } from "../src/Warehouse.sol";
import { Cast } from "../src/libraries/Cast.sol";

import { ERC20 } from "./utils/ERC20.sol";
import { WETH9 } from "./utils/WETH9.sol";
import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";

contract BaseTest is PRBTest, StdCheats {
    using Cast for uint256;
    using Cast for address;

    /* -------------------------------------------------------------------------- */
    /*                                  WAREHOUSE                                 */
    /* -------------------------------------------------------------------------- */

    Warehouse warehouse;

    string constant WAREHOUSE_NAME = "Splits Warehouse";
    string constant GAS_TOKEN_NAME = "Splits Wrapped Ether";
    string constant GAS_TOKEN_SYMBOL = "SplitsETH";

    /* -------------------------------------------------------------------------- */
    /*                                    USERS                                   */
    /* -------------------------------------------------------------------------- */

    address ALICE;
    address BOB;
    address CAROL;

    /* -------------------------------------------------------------------------- */
    /*                                   TOKENS                                   */
    /* -------------------------------------------------------------------------- */

    ERC20 usdc;
    ERC20 weth;
    WETH9 weth9;

    function setUp() public virtual {
        // Setup tokens
        usdc = new ERC20("USDC", "USDC");
        weth9 = new WETH9();
        weth = ERC20(address(weth9));

        // Setup users
        ALICE = createUser("ALICE");
        BOB = createUser("BOB");
        CAROL = createUser("CAROL");

        // Setup warehouse
        warehouse = new Warehouse(WAREHOUSE_NAME, GAS_TOKEN_NAME, GAS_TOKEN_SYMBOL);
    }

    function createUser(string memory name) internal returns (address payable user) {
        user = payable(makeAddr(name));
        vm.deal(user, 200 ether);
        deal(address(usdc), user, 100 ether);
        vm.prank(user);
        weth9.deposit{ value: 100 ether }();
    }

    function tokenToId(address token) internal pure returns (uint256 id) {
        id = token.toUint256();
    }

    function idToToken(uint256 id) internal pure returns (address token) {
        token = id.toAddress();
    }
}
