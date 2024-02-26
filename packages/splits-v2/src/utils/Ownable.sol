// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

/// @title Ownable Implementation
/// @author Splits
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
        emit OwnershipTransferred({ oldOwner: address(0), newOwner: _owner });
        owner = _owner;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier onlyOwner() virtual {
        if (msg.sender != owner && msg.sender != address(this)) revert Unauthorized();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    function transferOwnership(address _owner) public virtual onlyOwner {
        emit OwnershipTransferred({ oldOwner: owner, newOwner: _owner });
        owner = _owner;
    }
}
