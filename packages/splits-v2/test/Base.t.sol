// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { SplitsWarehouse } from "../src/SplitsWarehouse.sol";
import { Cast } from "../src/libraries/Cast.sol";

import { SplitV2Lib } from "../src/libraries/SplitV2.sol";
import { SplitFactoryV2 } from "../src/splitters/SplitFactoryV2.sol";
import { SplitWalletV2 } from "../src/splitters/SplitWalletV2.sol";

import { ERC20 } from "./utils/ERC20.sol";
import { WarehouseReentrantReceiver } from "./utils/ReentrantReceiver.sol";
import { WETH9 } from "./utils/WETH9.sol";
import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract BaseTest is PRBTest, StdCheats, StdInvariant, StdUtils {
    using Cast for uint256;
    using Cast for address;

    address[] internal assumeAddresses;

    /* -------------------------------------------------------------------------- */
    /*                                  WAREHOUSE                                 */
    /* -------------------------------------------------------------------------- */

    SplitsWarehouse warehouse;

    string constant WAREHOUSE_NAME = "Splits Warehouse";
    string constant GAS_TOKEN_NAME = "Splits Wrapped Ether";
    string constant GAS_TOKEN_SYMBOL = "SplitsETH";

    /* -------------------------------------------------------------------------- */
    /*                                    USERS                                   */
    /* -------------------------------------------------------------------------- */

    Account ALICE;
    Account BOB;
    Account CAROL;
    Account DAN;
    address BAD_ACTOR;

    /* -------------------------------------------------------------------------- */
    /*                                   TOKENS                                   */
    /* -------------------------------------------------------------------------- */

    address native;
    ERC20 usdc;
    ERC20 weth;
    WETH9 weth9;

    /* -------------------------------------------------------------------------- */
    /*                                  SPLITTERS                                 */
    /* -------------------------------------------------------------------------- */

    SplitFactoryV2 splitFactory;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    struct SplitReceiver {
        address receiver;
        uint32 allocation;
    }

    function setUp() public virtual {
        // Setup tokens
        usdc = new ERC20("USDC", "USDC");
        weth9 = new WETH9();
        weth = ERC20(address(weth9));

        // Setup users
        ALICE = createUser("ALICE");
        BOB = createUser("BOB");
        CAROL = createUser("CAROL");
        DAN = createUser("DAN");
        BAD_ACTOR = address(new WarehouseReentrantReceiver());

        // Setup warehouse
        warehouse = new SplitsWarehouse(GAS_TOKEN_NAME, GAS_TOKEN_SYMBOL);

        // Setup native token
        native = warehouse.NATIVE_TOKEN();

        // Setup split factory
        splitFactory = new SplitFactoryV2(address(warehouse));

        assumeAddresses.push(address(warehouse));
        assumeAddresses.push(address(usdc));
        assumeAddresses.push(address(weth));
        assumeAddresses.push(address(weth9));
        assumeAddresses.push(address(native));
        assumeAddresses.push(address(splitFactory));
        assumeAddresses.push(splitFactory.SPLIT_WALLET_IMPLEMENTATION());
    }

    function createUser(string memory name) internal returns (Account memory account) {
        (address user, uint256 pk) = makeAddrAndKey(name);
        return Account(user, pk);
    }

    function tokenToId(address token) internal pure returns (uint256 id) {
        id = token.toUint256();
    }

    function idToToken(uint256 id) internal pure returns (address token) {
        token = id.toAddress();
    }

    function assumeAddress(address addr) internal {
        assumeAddressIsNot(addr, AddressType.ForgeAddress, AddressType.Precompile, AddressType.ZeroAddress);
        for (uint256 i = 0; i < assumeAddresses.length; i++) {
            vm.assume(assumeAddresses[i] != addr);
        }
    }

    function createSplitParams(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush
    )
        internal
        pure
        returns (SplitV2Lib.Split memory)
    {
        vm.assume(_receivers.length <= 100);
        uint256 totalAllocation;
        uint256[] memory allocations = new uint256[](_receivers.length);
        address[] memory recipients = new address[](_receivers.length);

        for (uint256 i = 0; i < _receivers.length; i++) {
            vm.assume(_receivers[i].receiver != address(0));
            totalAllocation += uint256(_receivers[i].allocation);
            allocations[i] = _receivers[i].allocation;
            recipients[i] = _receivers[i].receiver;
        }

        return SplitV2Lib.Split(recipients, allocations, totalAllocation, _distributionIncentive, _distributeByPush);
    }

    function predictCreateAddress(address addr, uint256 nonce) internal pure returns (address) {
        return computeCreateAddress(addr, nonce);
    }

    function createSplit(
        SplitReceiver[] memory _receivers,
        uint16 _distributionIncentive,
        bool _distributeByPush,
        address _owner,
        address _creator
    )
        internal
        returns (address split)
    {
        split = splitFactory.createSplit(
            createSplitParams(_receivers, _distributionIncentive, _distributeByPush), _owner, _creator
        );
    }
}
