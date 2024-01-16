// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { SplitsWarehouse } from "../../src/SplitsWarehouse.sol";

/* solhint-disable */
contract WarehouseReentrantReceiver {
    fallback() external payable {
        address token = SplitsWarehouse(msg.sender).NATIVE_TOKEN();
        SplitsWarehouse(msg.sender).withdraw(token, msg.value);
    }
}
