// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Ownable } from "solady/auth/Ownable.sol";
import { Signer } from "src/signers/Signer.sol";
import { MultiSigner } from "src/utils/MultiSigner.sol";

contract MultiSignerMock is MultiSigner, Ownable {
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

    function initialize(address _root, Signer[] calldata _signers, uint8 _threshold) external {
        if (msg.sender != deployer) revert();
        _initializeOwner(_root);
        _initializeSigners(_signers, _threshold);
    }

    function _authorize() internal view override(MultiSigner) onlyOwner { }
}
