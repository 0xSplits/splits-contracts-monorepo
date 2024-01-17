// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import { Cast } from "../../src/libraries/Cast.sol";
import { ERC6909Permit } from "../../src/tokens/ERC6909Permit.sol";

contract ERC6909Test is ERC6909Permit {
    using Cast for address;

    constructor(string memory name, string memory version) ERC6909Permit(name, version) { }

    function mint(uint256 _id, uint256 _amount) public {
        _mint(msg.sender, _id, _amount);
    }

    function burn(uint256 _id, uint256 _amount) public {
        _burn(msg.sender, _id, _amount);
    }
}
