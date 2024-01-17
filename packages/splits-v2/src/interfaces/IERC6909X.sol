// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

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
        uint256 deadline,
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
        uint256 deadline,
        bytes calldata signature
    )
        external
        returns (bool);
}
