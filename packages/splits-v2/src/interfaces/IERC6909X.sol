// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/**
 * @author https://github.com/frangio/erc6909-extensions
 */
interface IERC6909X is IERC5267 {
    function temporaryApproveAndCall(
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes calldata data
    )
        external
        returns (bool);

    function temporaryApproveAndCallBySig(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        address target,
        bytes calldata data,
        uint256 nonce,
        uint48 deadline,
        bytes calldata signature
    )
        external
        returns (bool);

    function approveBySig(
        address owner,
        address spender,
        bool operator,
        uint256 id,
        uint256 amount,
        uint256 nonce,
        uint48 deadline,
        bytes calldata signature
    )
        external
        returns (bool);
}
