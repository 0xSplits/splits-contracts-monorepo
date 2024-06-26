// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitsWarehouse } from "../../src/SplitsWarehouse.sol";

/* solhint-disable */
contract WarehouseReentrantReceiver {
    fallback() external payable {
        address token = SplitsWarehouse(msg.sender).NATIVE_TOKEN();
        SplitsWarehouse(msg.sender).withdraw(msg.sender, token);
    }
}
