// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { RootOwner } from "src/utils/RootOwner.sol";

contract RootOwnerMock is RootOwner {
    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event Transfer();

    /* -------------------------------------------------------------------------- */
    /*                                 constructor                                */
    /* -------------------------------------------------------------------------- */

    constructor() { }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function initialize(address _root) external {
        initializeRoot(_root);
    }

    function transferRoot() external onlyRoot {
        emit Transfer();
    }

    function root() public view returns (address) {
        return getRoot();
    }

    function transferRootOpen() external {
        (bool success, bytes memory result) = address(this).call{ value: 0 }(abi.encode(this.transferRoot.selector));
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
