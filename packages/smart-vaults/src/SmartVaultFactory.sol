// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";

import { SmartVault } from "./SmartVault.sol";

/**
 * @dev forked from
 * https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccountFactory.sol
 */
contract SmartVaultFactory {
    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice smart vault implementation
    SmartVault public immutable accountImplementation;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(address _entryPoint) {
        accountImplementation = new SmartVault(_entryPoint);
    }

    /* -------------------------------------------------------------------------- */
    /*                             EXTERNAL FUNCTIONS                             */
    /* -------------------------------------------------------------------------- */

    /**
     * create an account, and return its address.
     * returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after
     * account creation
     */
    function createAccount(address _root, bytes32 _salt) public returns (SmartVault ret) {
        address addr = getAddress(_root, _salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return SmartVault(payable(addr));
        }
        ret = SmartVault(
            payable(
                new ERC1967Proxy{ salt: _salt }(
                    address(accountImplementation), abi.encodeCall(SmartVault.initialize, (_root))
                )
            )
        );
    }

    /**
     * calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getAddress(address _root, bytes32 _salt) public view returns (address) {
        return Create2.computeAddress(
            _salt,
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(address(accountImplementation), abi.encodeCall(SmartVault.initialize, (_root)))
                )
            )
        );
    }
}
