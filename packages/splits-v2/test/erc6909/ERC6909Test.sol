// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Cast } from "../../src/libraries/Cast.sol";
import { ERC6909X } from "../../src/tokens/ERC6909X.sol";

contract ERC6909Test is ERC6909X {
    using Cast for address;

    constructor(string memory name, string memory version) ERC6909X(name, version) { }

    function mint(uint256 _id, uint256 _amount) public {
        _mint(msg.sender, _id, _amount);
    }

    function burn(uint256 _id, uint256 _amount) public {
        _burn(msg.sender, _id, _amount);
    }
}
