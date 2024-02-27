// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { SplitFactoryV2 } from "../SplitFactoryV2.sol";
import { PushSplit } from "./PushSplit.sol";

/**
 * @title Push split factory
 * @author Splits
 * @notice Minimal smart wallet clone-factory for push flow splitters.
 */
contract PushSplitFactory is SplitFactoryV2 {
    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(address _splitsWarehouse) {
        SPLIT_WALLET_IMPLEMENTATION = address(new PushSplit(_splitsWarehouse));
    }
}
