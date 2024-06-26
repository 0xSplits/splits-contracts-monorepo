// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

contract BaseTest is PRBTest, StdCheats, StdInvariant, StdUtils {
    address[] internal assumeAddresses;

    /* -------------------------------------------------------------------------- */
    /*                                    USERS                                   */
    /* -------------------------------------------------------------------------- */

    Account ALICE;
    Account BOB;
    Account CAROL;
    Account DAN;

    /* -------------------------------------------------------------------------- */
    /*                                   TOKENS                                   */
    /* -------------------------------------------------------------------------- */

    function setUp() public virtual {
        // Setup users
        ALICE = createUser("ALICE");
        BOB = createUser("BOB");
        CAROL = createUser("CAROL");
        DAN = createUser("DAN");
    }

    function createUser(string memory name) internal returns (Account memory account) {
        (address user, uint256 pk) = makeAddrAndKey(name);
        return Account(user, pk);
    }
}
