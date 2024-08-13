// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Test, console2, stdError } from "forge-std/Test.sol";

import { Signer } from "src/signers/Signer.sol";
import { SmartVaultFactory } from "src/vault/SmartVaultFactory.sol";

function createSigner(address signer_) pure returns (Signer memory) {
    return Signer(bytes32(uint256(uint160(signer_))), bytes32(0));
}

function createSigner(uint256 x_, uint256 y_) pure returns (Signer memory) {
    return Signer(bytes32(x_), bytes32(y_));
}

contract BaseTest is Test {
    address[] internal assumeAddresses;

    /* -------------------------------------------------------------------------- */
    /*                                    USERS                                   */
    /* -------------------------------------------------------------------------- */

    Account ALICE;
    Account BOB;
    Account CAROL;
    Account DAN;

    /* -------------------------------------------------------------------------- */
    /*                             SMART VAULT FACTORY                            */
    /* -------------------------------------------------------------------------- */

    SmartVaultFactory smartVaultFactory;

    function setUp() public virtual {
        // Setup users
        ALICE = createUser("ALICE");
        BOB = createUser("BOB");
        CAROL = createUser("CAROL");
        DAN = createUser("DAN");

        smartVaultFactory = new SmartVaultFactory();
    }

    function createUser(string memory name) internal returns (Account memory account) {
        (address user, uint256 pk) = makeAddrAndKey(name);
        return Account(user, pk);
    }

    function assertEq(Signer memory signer1, Signer memory signer2) internal pure {
        assertEq(signer1.slot1, signer2.slot1);
        assertEq(signer1.slot2, signer2.slot2);
    }
}
