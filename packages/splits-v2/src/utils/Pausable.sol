// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.18;

import { Ownable } from "./Ownable.sol";

/**
 * @title Pausable Implementation
 * @author Splits
 * @notice Pausable clone-implementation
 */
abstract contract Pausable is Ownable {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    error Paused();

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    event SetPaused(bool paused);

    /* -------------------------------------------------------------------------- */
    /*                                   STORAGE                                  */
    /* -------------------------------------------------------------------------- */

    bool public paused;

    /* -------------------------------------------------------------------------- */
    /*                          CONSTRUCTOR & INITIALIZER                         */
    /* -------------------------------------------------------------------------- */

    function __initPausable(address _owner, bool _paused) internal virtual {
        __initOwnable(_owner);
        paused = _paused;
    }

    /* -------------------------------------------------------------------------- */
    /*                                  MODIFIERS                                 */
    /* -------------------------------------------------------------------------- */

    modifier pausable() virtual {
        if (paused && msg.sender != owner) revert Paused();
        _;
    }

    /* -------------------------------------------------------------------------- */
    /*                          PUBLIC/EXTERNAL FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function setPaused(bool _paused) public virtual onlyOwner {
        paused = _paused;
        emit SetPaused(_paused);
    }
}
