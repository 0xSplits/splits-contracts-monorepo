// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Warehouse } from "../src/Warehouse.sol";
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

    Warehouse warehouse;

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
        warehouse = new Warehouse(WAREHOUSE_NAME, GAS_TOKEN_NAME, GAS_TOKEN_SYMBOL);

        // Setup native token
        native = warehouse.NATIVE_TOKEN();

        assumeAddresses.push(address(warehouse));
        assumeAddresses.push(address(usdc));
        assumeAddresses.push(address(weth));
        assumeAddresses.push(address(weth9));
        assumeAddresses.push(address(native));

        // Setup split factory
        splitFactory = new SplitFactoryV2(address(warehouse));
    }

    function createUser(string memory name) internal returns (Account memory account) {
        (address user, uint256 pk) = makeAddrAndKey(name);
        vm.deal(user, 200 ether);
        deal(address(usdc), user, 100 ether);
        vm.prank(user);
        weth9.deposit{ value: 100 ether }();

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

    function createSplit(
        SplitReceiver[] memory _recievers,
        uint256 _pushIncentive,
        uint256 _pullIncentive
    )
        internal
        pure
        returns (SplitV2Lib.Split memory)
    {
        uint256 totalAllocation;
        uint32[] memory allocations = new uint32[](_recievers.length);
        address[] memory recipients = new address[](_recievers.length);

        for (uint256 i = 0; i < _recievers.length; i++) {
            totalAllocation += uint256(_recievers[i].allocation);
            allocations[i] = _recievers[i].allocation;
            recipients[i] = _recievers[i].receiver;
        }

        _pushIncentive = bound(_pushIncentive, 0, SplitV2Lib.MAX_INCENTIVE);
        _pullIncentive = bound(_pullIncentive, 0, SplitV2Lib.MAX_INCENTIVE);

        return SplitV2Lib.Split(recipients, allocations, totalAllocation, _pushIncentive, _pullIncentive);
    }

    /* solhint-disable */
    /// forked from https://github.com/pcaversaccio/create-util/blob/main/contracts/Create.sol#L94
    function predictCreateAddress(address addr, uint256 nonce) internal pure returns (address) {
        bytes memory data;
        bytes1 len = bytes1(0x94);

        /**
         * @dev The theoretical allowed limit, based on EIP-2681, for an account nonce is 2**64-2:
         * https://eips.ethereum.org/EIPS/eip-2681.
         */
        if (nonce > type(uint64).max - 1) revert("Invalid nonce");

        /**
         * @dev The integer zero is treated as an empty byte string and therefore has only one
         * length prefix, 0x80, which is calculated via 0x80 + 0.
         */
        if (nonce == 0x00) {
            data = abi.encodePacked(bytes1(0xd6), len, addr, bytes1(0x80));
        }
        /**
         * @dev A one-byte integer in the [0x00, 0x7f] range uses its own value as a length prefix,
         * there is no additional "0x80 + length" prefix that precedes it.
         */
        else if (nonce <= 0x7f) {
            data = abi.encodePacked(bytes1(0xd6), len, addr, uint8(nonce));
        }
        /**
         * @dev In the case of `nonce > 0x7f` and `nonce <= type(uint8).max`, we have the following
         * encoding scheme (the same calculation can be carried over for higher nonce bytes):
         * 0xda = 0xc0 (short RLP prefix) + 0x1a (= the bytes length of: 0x94 + address + 0x84 + nonce, in hex),
         * 0x94 = 0x80 + 0x14 (= the bytes length of an address, 20 bytes, in hex),
         * 0x84 = 0x80 + 0x04 (= the bytes length of the nonce, 4 bytes, in hex).
         */
        else if (nonce <= type(uint8).max) {
            data = abi.encodePacked(bytes1(0xd7), len, addr, bytes1(0x81), uint8(nonce));
        } else if (nonce <= type(uint16).max) {
            data = abi.encodePacked(bytes1(0xd8), len, addr, bytes1(0x82), uint16(nonce));
        } else if (nonce <= type(uint24).max) {
            data = abi.encodePacked(bytes1(0xd9), len, addr, bytes1(0x83), uint24(nonce));
        } else if (nonce <= type(uint32).max) {
            data = abi.encodePacked(bytes1(0xda), len, addr, bytes1(0x84), uint32(nonce));
        } else if (nonce <= type(uint40).max) {
            data = abi.encodePacked(bytes1(0xdb), len, addr, bytes1(0x85), uint40(nonce));
        } else if (nonce <= type(uint48).max) {
            data = abi.encodePacked(bytes1(0xdc), len, addr, bytes1(0x86), uint48(nonce));
        } else if (nonce <= type(uint56).max) {
            data = abi.encodePacked(bytes1(0xdd), len, addr, bytes1(0x87), uint56(nonce));
        } else {
            data = abi.encodePacked(bytes1(0xde), len, addr, bytes1(0x88), uint64(nonce));
        }

        return address(uint160(uint256(keccak256(data))));
    }
    /* solhint-enable */

    function getCreatSplitParams(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner,
        address _creator
    )
        internal
        pure
        returns (SplitFactoryV2.CreateSplitParams memory)
    {
        SplitV2Lib.Split memory splitParams = createSplit(_receivers, _pullIncentive, _pushIncentive);

        return SplitFactoryV2.CreateSplitParams({ split: splitParams, owner: _owner, creator: _creator });
    }

    function createSplit(
        SplitReceiver[] memory _receivers,
        uint256 _pullIncentive,
        uint256 _pushIncentive,
        address _owner,
        address _creator
    )
        internal
        returns (address split)
    {
        SplitFactoryV2.CreateSplitParams memory params =
            getCreatSplitParams(_receivers, _pullIncentive, _pushIncentive, _owner, _creator);

        split = splitFactory.createSplit(params);
    }
}
