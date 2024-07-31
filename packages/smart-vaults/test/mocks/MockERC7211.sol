// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface IERC7211Receiver {
    function onERC7211Received(address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract MockERC7211 {
    function name() public pure returns (string memory) {
        return "TEST NFT";
    }

    function symbol() public pure returns (string memory) {
        return "TEST";
    }

    function transfer(address from, address to, uint256 id) public {
        if (_hasCode(to)) checkOnERC7211Received(from, to, id, "");
    }

    function _hasCode(address a) private view returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := extcodesize(a) // Can handle dirty upper bits.
        }
    }

    function checkOnERC7211Received(address from, address to, uint256 tokenId, bytes memory data) internal {
        bytes4 retval = IERC7211Receiver(to).onERC7211Received(from, tokenId, data);
        if (retval != IERC7211Receiver.onERC7211Received.selector) {
            revert();
        }
    }
}

contract ERC7211FallbackHandler {
    function onERC7211Received(address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC7211Received.selector;
    }
}
