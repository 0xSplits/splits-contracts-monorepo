// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import { ERC6909Permit } from "./tokens/ERC6909Permit.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import { Cast } from "./libraries/Cast.sol";

/**
 * @title Splits token Warehouse
 * @author Splits
 * @notice ERC6909 compliant token warehouse for splits ecosystem of splitters
 * @dev Token id here is address(uint160(uint256 id)). This contract automatically wraps eth to weth and
 * vice versa.
 */
contract Warehouse is ERC6909Permit {
    using Cast for uint256;

    /* -------------------------------------------------------------------------- */
    /*                            CONSTANTS/IMMUTABLES                            */
    /* -------------------------------------------------------------------------- */

    string constant METADATA_PREFIX_SYMBOL = "Splits";
    string constant METADATA_PREFIX_NAME = "Splits Wrapped ";

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Total supply of a token
    mapping(uint256 id => uint256 amount) public totalSupply;

    /* -------------------------------------------------------------------------- */
    /*                                 CONSTRUCTOR                                */
    /* -------------------------------------------------------------------------- */

    constructor(string memory _name) ERC6909Permit(_name) { }

    /* -------------------------------------------------------------------------- */
    /*                               ERC6909METADATA                              */
    /* -------------------------------------------------------------------------- */

    /// @notice Name of a given token.
    /// @param id The id of the token.
    /// @return name The name of the token.
    function name(uint256 id) external view returns (string memory) {
        return string.concat(METADATA_PREFIX_NAME, IERC20Metadata(id.toAddress()).name());
    }

    /// @notice Symbol of a given token.
    /// @param id The id of the token.
    /// @return symbol The symbol of the token.
    function symbol(uint256 id) external view returns (string memory) {
        return string.concat(METADATA_PREFIX_SYMBOL, IERC20Metadata(id.toAddress()).name());
    }

    /// @notice Decimals of a given token.
    /// @param id The id of the token.
    /// @return decimals The decimals of the token.
    function decimals(uint256 id) external view returns (uint8) {
        return IERC20Metadata(id.toAddress()).decimals();
    }
}
