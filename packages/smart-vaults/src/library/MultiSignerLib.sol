// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title Multi Signer Library
 * @author Splits
 */
library MultiSignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice Thrown when a provided signer is neither 64 bytes long (for public key)
     *         nor a ABI encoded address.
     * @param signer The invalid signer.
     */
    error InvalidSignerBytesLength(bytes signer);

    /**
     * @notice Thrown if a provided signer is 32 bytes long but does not fit in an `address` type or if `signer` has
     * code.
     * @param signer The invalid signer.
     */
    error InvalidEthereumAddressOwner(bytes signer);

    /// @notice Thrown when threshold is greater than number of owners or when zero.
    error InvalidThreshold();

    /// @notice Thrown when number of signers is more than 256.
    error InvalidNumberOfSigners();

    function validateSigners(bytes[] calldata _signers, uint8 _threshold) internal view {
        if (_signers.length > 255 || _signers.length == 0) revert InvalidNumberOfSigners();

        uint8 numberOfSigners = uint8(_signers.length);

        if (numberOfSigners < _threshold || _threshold < 1) revert InvalidThreshold();

        bytes memory signer;

        for (uint8 i; i < numberOfSigners; i++) {
            signer = _signers[i];

            validateSigner(signer);
        }
    }

    function validateSigner(bytes memory _signer) internal view {
        if (_signer.length != 32 && _signer.length != 64) {
            revert InvalidSignerBytesLength(_signer);
        }

        if (_signer.length == 32) {
            if (uint256(bytes32(_signer)) > type(uint160).max) revert InvalidEthereumAddressOwner(_signer);
            address eoa;
            assembly ("memory-safe") {
                eoa := mload(add(_signer, 32))
            }

            if (eoa.code.length > 0) revert InvalidEthereumAddressOwner(_signer);
        }
    }
}
