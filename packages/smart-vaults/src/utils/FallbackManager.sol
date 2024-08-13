// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Receiver } from "solady/accounts/Receiver.sol";

/**
 * @title Fallback Manager - Fallback call handler for a smart contract.
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 * @dev By defaults supports all ERC721 and ERC1155 token safety callbacks.
 */
abstract contract FallbackManager is Receiver {
    /* -------------------------------------------------------------------------- */
    /*                                  CONSTANTS                                 */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Slot for the `FallbackManager` struct in storage.
     *      Computed from
     *      keccak256(abi.encode(uint256(keccak256("splits.storage.FallbackManager")) - 1)) & ~bytes32(uint256(0xff))
     *      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
     */
    bytes32 internal constant _FALLBACK_MANAGER_STORAGE_SLOT =
        0xb944faae3883660fcc8ae340f6a7654d66dcad30db4f2f608a0b893e0f339a00;

    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    /// @notice Fallback Manager storage structure
    struct FallbackManagerStorage {
        mapping(bytes4 => address) fallbackHandler;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   EVENTS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Event emitted when a new Fallback Handler is registered.
    event UpdatedFallbackHandler(bytes4 indexed sig, address indexed handler);

    /// @notice Event emitted when this contract receives ETH.
    event ReceiveEth(address indexed sender, uint256 amount);

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when a function is not supported by the FallbackHandler.
    error FunctionNotSupported(bytes4 sig);

    /* -------------------------------------------------------------------------- */
    /*                          EXTERNAL/PUBLIC FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    /**
     * @dev Fallback function to handle unsupported function calls.
     * It checks if a handler is set for the given function signature and
     * if so, forwards the call to the handler.
     */
    fallback() external payable override receiverFallback {
        address handler = _getFallbackManagerStorage().fallbackHandler[msg.sig];

        if (handler == address(0)) {
            revert FunctionNotSupported(msg.sig);
        }

        (bool success, bytes memory result) = handler.call(msg.data);

        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }

        assembly ("memory-safe") {
            return(add(result, 0x20), mload(result))
        }
    }

    /// @notice Receive function that logs the amount of ETH received.
    receive() external payable override {
        emit ReceiveEth(msg.sender, msg.value);
    }

    /**
     * @notice Allows setting a handler for a given function signature.
     *
     * @dev Following signatures is handled automatically by this contract and does not need any handler.
     *      - 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
     *      - 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
     *      - 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
     *
     * @param sig_ The function signature for which the handler is being set.
     * @param handler_ The address of the handler contract.
     */
    function updateFallbackHandler(bytes4 sig_, address handler_) public {
        _authorize();

        _getFallbackManagerStorage().fallbackHandler[sig_] = handler_;

        emit UpdatedFallbackHandler(sig_, handler_);
    }

    /**
     * @notice Returns the fallback handler associated with the provided `sig`.
     * @param sig_ bytes4 signature.
     * @return handler address of contract that receives the call for `sig`.
     */
    function getFallbackHandler(bytes4 sig_) public view returns (address) {
        return _getFallbackManagerStorage().fallbackHandler[sig_];
    }

    /* -------------------------------------------------------------------------- */
    /*                         INTERNAL/PRIVATE FUNCTIONS                         */
    /* -------------------------------------------------------------------------- */

    function _authorize() internal view virtual;

    function _getFallbackManagerStorage() internal pure returns (FallbackManagerStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _FALLBACK_MANAGER_STORAGE_SLOT
        }
    }
}
