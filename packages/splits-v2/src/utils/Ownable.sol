// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @title Ownable Implementation
/// @author 0xSplits
/// @notice Ownable clone-implementation
abstract contract Ownable {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error Unauthorized();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    address public owner;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    function __initOwnable(address _owner) internal virtual {
        emit OwnershipTransferred(address(0), _owner);
        owner = _owner;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyOwner() virtual {
        if (msg.sender != owner && owner != address(this)) revert Unauthorized();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function transferOwnership(address _owner) public virtual onlyOwner {
        owner = _owner;
        emit OwnershipTransferred(msg.sender, _owner);
    }
}
