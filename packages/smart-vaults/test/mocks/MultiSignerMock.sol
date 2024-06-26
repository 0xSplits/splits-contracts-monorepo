// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MultiSigner } from "src/utils/MultiSigner.sol";
import { RootOwner } from "src/utils/RootOwner.sol";

contract MultiSignerMock is MultiSigner, RootOwner {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    address immutable deployer;
    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event Transfer();

    /* -------------------------------------------------------------------------- */
    /*                                 constructor                                */
    /* -------------------------------------------------------------------------- */

    constructor() {
        deployer = msg.sender;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function initialize(address _root, bytes[] calldata _signers, uint8 _threshold) external {
        if (msg.sender != deployer) revert();
        initializeRoot(_root);
        initializeSigners(_signers, _threshold);
    }

    function authorizeUpdate() internal view override(MultiSigner) onlyRoot { }
}
