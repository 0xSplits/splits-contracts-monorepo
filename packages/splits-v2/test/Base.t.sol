// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitsWarehouse } from "../src/SplitsWarehouse.sol";
import { Cast } from "../src/libraries/Cast.sol";

import { SplitV2Lib } from "../src/libraries/SplitV2.sol";

import { PullSplit } from "../src/splitters/pull/PullSplit.sol";
import { PullSplitFactory } from "../src/splitters/pull/PullSplitFactory.sol";
import { PushSplit } from "../src/splitters/push/PushSplit.sol";
import { PushSplitFactory } from "../src/splitters/push/PushSplitFactory.sol";

import { ERC20 } from "./utils/ERC20.sol";
import { ERC6909XUtils } from "./utils/ERC6909XUtils.sol";
import { WarehouseReentrantReceiver } from "./utils/ReentrantReceiver.sol";
import { WETH9 } from "./utils/WETH9.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract BaseTest is PRBTest, StdCheats, StdInvariant, StdUtils {
    using Cast for uint256;
    using Cast for address;
    using SafeERC20 for IERC20;

    address[] internal assumeAddresses;

    /* -------------------------------------------------------------------------- */
    /*                                  WAREHOUSE                                 */
    /* -------------------------------------------------------------------------- */

    SplitsWarehouse warehouse;

    ERC6909XUtils public permitUtils;

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

    PullSplitFactory pullFactory;
    PushSplitFactory pushFactory;

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

        permitUtils = new ERC6909XUtils(warehouse.DOMAIN_SEPARATOR());

        // Setup split factory
        pullFactory = new PullSplitFactory(address(warehouse));
        pushFactory = new PushSplitFactory(address(warehouse));

        assumeAddresses.push(address(warehouse));
        assumeAddresses.push(address(usdc));
        assumeAddresses.push(address(weth));
        assumeAddresses.push(address(weth9));
        assumeAddresses.push(address(native));
        assumeAddresses.push(address(pullFactory));
        assumeAddresses.push(address(pushFactory));
        assumeAddresses.push(pullFactory.SPLIT_WALLET_IMPLEMENTATION());
        assumeAddresses.push(pushFactory.SPLIT_WALLET_IMPLEMENTATION());
        assumeAddresses.push(address(permitUtils));
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
        uint16 _distributionIncentive
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

        return SplitV2Lib.Split(recipients, allocations, totalAllocation, _distributionIncentive);
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
        returns (address split, SplitV2Lib.Split memory params)
    {
        params = createSplitParams(_receivers, _distributionIncentive);
        if (_distributeByPush) {
            split = pushFactory.createSplit(params, _owner, _creator);
        } else {
            split = pullFactory.createSplit(params, _owner, _creator);
        }
    }

    function dealSplit(address _split, address _token, uint256 _splitAmount, uint256 _warehouseAmount) internal {
        if (_token == native) deal(_split, _splitAmount);
        else deal(_token, _split, _splitAmount);

        address depositor = createUser("depositor").addr;
        if (_token == native) deal(depositor, _warehouseAmount);
        else deal(_token, depositor, _warehouseAmount);

        vm.startPrank(depositor);

        if (_token == native) {
            warehouse.deposit{ value: _warehouseAmount }(_split, _token, _warehouseAmount);
        } else {
            IERC20(_token).forceApprove(address(warehouse), _warehouseAmount);
            warehouse.deposit(_split, _token, _warehouseAmount);
        }
        vm.stopPrank();
    }

    function getPermitSignature(
        bool _temporary,
        address _owner,
        uint256 _key,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint48 _deadline
    )
        public
        view
        returns (bytes memory signature)
    {
        bytes32 digest =
            getDigest(_temporary, _owner, _spender, _isOperator, _id, _value, _target, _data, _nonce, _deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function getDigest(
        bool _temporary,
        address _owner,
        address _spender,
        bool _isOperator,
        uint256 _id,
        uint256 _value,
        address _target,
        bytes memory _data,
        uint256 _nonce,
        uint48 _deadline
    )
        public
        view
        returns (bytes32 digest)
    {
        ERC6909XUtils.ERC6909XApproveAndCall memory permit = ERC6909XUtils.ERC6909XApproveAndCall({
            temporary: _temporary,
            owner: _owner,
            spender: _spender,
            isOperator: _isOperator,
            id: _id,
            amount: _value,
            target: _target,
            data: _data,
            nonce: _nonce,
            deadline: _deadline
        });

        digest = permitUtils.getTypedDataHash(permit);
    }

    // solhint-disable-next-line code-complexity
    function assertDistribute(
        SplitV2Lib.Split memory _split,
        address _token,
        uint256 _warehouseAmount,
        uint256 _splitAmount,
        address _distributor,
        bool _distributeByPush
    )
        internal
    {
        if (_warehouseAmount > 0) _warehouseAmount -= 1;
        if (_splitAmount > 0) _splitAmount -= 1;

        uint256 totalAmount = _warehouseAmount + _splitAmount;

        (uint256[] memory amounts, uint256 reward) = SplitV2Lib.getDistributionsMem(_split, totalAmount);

        if (_distributeByPush) {
            if (_token == native) {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    uint256 balance = address(_split.recipients[i]).balance
                        + warehouse.balanceOf(_split.recipients[i], tokenToId(_token));
                    assertGte(balance, amounts[i]);
                }
                if (reward > 0) {
                    assertGte(_distributor.balance, reward);
                }
            } else {
                for (uint256 i = 0; i < _split.recipients.length; i++) {
                    assertGte(IERC20(_token).balanceOf(_split.recipients[i]), amounts[i]);
                }
                if (reward > 0) {
                    assertGte(IERC20(_token).balanceOf(_distributor), reward);
                }
            }
        } else {
            for (uint256 i = 0; i < _split.recipients.length; i++) {
                assertGte(warehouse.balanceOf(_split.recipients[i], tokenToId(_token)), amounts[i]);
            }
            assertGte(warehouse.balanceOf(_distributor, tokenToId(_token)), reward);
        }
    }
}
