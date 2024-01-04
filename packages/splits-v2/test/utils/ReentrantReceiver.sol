// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Warehouse } from "../../src/Warehouse.sol";

/* solhint-disable */
contract WarehouseReentrantReceiver {
    fallback() external payable {
        address token = Warehouse(msg.sender).NATIVE_TOKEN();
        Warehouse(msg.sender).withdraw(token, msg.value);
    }
}
