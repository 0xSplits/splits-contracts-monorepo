// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.23;

import { Signer } from "../signers/Signer.sol";

/**
 * @notice Multi Signer struct.
 * @dev Each signer is of type `Signer`.
 * @dev Can allow up to 256 signers.
 */
struct MultiSigner {
    /// @dev Number of unique signatures required to validate a message signed by this contract.
    uint8 threshold;
    /// @dev number of signers
    uint8 signerCount;
    /// @dev signers of type `Signer`;
    mapping(uint8 => Signer) signers;
}

using MultiSignerLib for MultiSigner global;

/**
 * @title Multi Signer Library
 * @custom:security-contract security@splits.org
 * @author Splits (https://splits.org)
 */
library MultiSignerLib {
    /* -------------------------------------------------------------------------- */
    /*                                   STRUCTS                                  */
    /* -------------------------------------------------------------------------- */

    struct SignatureWrapper {
        /// @dev The index of the signer that signed, see `MultiSigner.signerAtIndex`
        uint8 signerIndex;
        /**
         * @dev If `MultiSigner.signerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
         *      If `MultiSigner.signerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
         */
        bytes signatureData;
    }

    /* -------------------------------------------------------------------------- */
    /*                                   ERRORS                                   */
    /* -------------------------------------------------------------------------- */

    /// @notice Thrown when Signer is invalid.
    error InvalidSigner(Signer signer);

    /// @notice Thrown when threshold is greater than number of owners or when zero.
    error InvalidThreshold();

    /// @notice Thrown when number of signers is more than 256.
    error InvalidNumberOfSigners();

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Get signer at index from storage.
    function getSigner(MultiSigner storage $_, uint8 index_) internal view returns (Signer memory) {
        return $_.signers[index_];
    }

    /// @notice get threshold from storage.
    function getThreshold(MultiSigner storage $_) internal view returns (uint8) {
        return $_.threshold;
    }

    /// @notice get number of signers from storage.
    function getSignerCount(MultiSigner storage $_) internal view returns (uint8) {
        return $_.signerCount;
    }

    /**
     * @notice Sets signer at index in storage.
     *
     * @dev Throws error when signer is not EOA or Passkey.
     *
     * @param $_ multi signer storage reference.
     * @param signer_ Signer to be set.
     * @param index_ Index to set signer at.
     */
    function addSigner(MultiSigner storage $_, Signer calldata signer_, uint8 index_) internal {
        if (signer_.isPasskey()) {
            /// if passkey store signer as is.
            $_.signers[index_] = signer_;
        } else if (signer_.isEOA()) {
            /// if EOA only store slot1 since slot2 is zero.
            $_.signers[index_].slot1 = signer_.slot1;
        } else {
            revert InvalidSigner(signer_);
        }
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @param index_ The index of the signer to be removed.
     */
    function removeSigner(MultiSigner storage $_, uint8 index_) internal {
        delete $_.signers[index_];
    }

    /**
     * @notice Updates threshold of the signer set.
     *
     * @param threshold_ The new signer set threshold.
     */
    function updateThreshold(MultiSigner storage $_, uint8 threshold_) internal {
        $_.threshold = threshold_;
    }

    /**
     * @notice Updates threshold of the signer set.
     *
     * @param signerCount_ The new signer set threshold.
     */
    function updateSignerCount(MultiSigner storage $_, uint8 signerCount_) internal {
        $_.signerCount = signerCount_;
    }

    /**
     * @notice Validates the list of `signers` and `threshold`.
     *
     * @dev Throws error when number of signers is zero or greater than 255.
     * @dev Throws error if `threshold` is zero or greater than number of signers.
     *
     * @param signers_ List of Signer(s).
     * @param threshold_ minimum number of signers required for approval.
     */
    function validateSigners(Signer[] calldata signers_, uint8 threshold_) internal pure {
        if (signers_.length > type(uint8).max || signers_.length == 0) revert InvalidNumberOfSigners();

        uint8 numberOfSigners = uint8(signers_.length);

        if (numberOfSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        for (uint8 i; i < numberOfSigners; i++) {
            validateSigner(signers_[i]);
        }
    }

    /**
     * @notice Validates the signer.
     *
     * @dev Throws error when signer is neither an EOA or a passkey.
     */
    function validateSigner(Signer calldata signer_) internal pure {
        if (!signer_.isValid()) revert InvalidSigner(signer_);
    }

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$_`
     *
     * @param $_ Storage reference to MultiSigner storage.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ List of signatureWrapper
     */
    function isValidSignature(
        MultiSigner storage $_,
        bytes32 hash_,
        SignatureWrapper[] memory signatures_
    )
        internal
        view
        returns (bool isValid)
    {
        return isValidSignature($_, hash_, hash_, signatures_);
    }

    /**
     * @notice validates if a pair of hashes was signed by the signer set present in `$_`.
     *
     * @param $_ Storage reference to MultiSigner storage.
     * @param frontHash_ blob of data that should be signed by all but the last signer.
     * @param backHash_ blob of data that should be signed by the last signer.
     * @param signatures_ List of signatureWrapper
     */
    function isValidSignature(
        MultiSigner storage $_,
        bytes32 frontHash_,
        bytes32 backHash_,
        SignatureWrapper[] memory signatures_
    )
        internal
        view
        returns (bool isValid)
    {
        isValid = true;

        uint8 threshold = $_.threshold;

        uint256 alreadySigned;

        uint256 mask;
        uint8 signerIndex;
        uint256 i;
        for (; i < threshold - 1; i++) {
            signerIndex = signatures_[i].signerIndex;
            mask = (1 << signerIndex);

            if (
                $_.signers[signerIndex].isValidSignature(frontHash_, signatures_[i].signatureData)
                    && alreadySigned & mask == 0
            ) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }

        signerIndex = signatures_[i].signerIndex;
        mask = (1 << signerIndex);

        if (
            $_.signers[signerIndex].isValidSignature(backHash_, signatures_[i].signatureData)
                && alreadySigned & mask == 0
        ) {
            alreadySigned |= mask;
        } else {
            isValid = false;
        }
    }
}
