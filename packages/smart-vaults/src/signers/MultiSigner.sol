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
    Signer[256] signers;
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

    /**
     * @notice Thrown when trying to remove an empty signer.
     * @param index Index of the empty signer.
     */
    error SignerNotPresent(uint8 index);

    /**
     * @notice Thrown when trying to replace an existing signer.
     * @param index Index of the existing signer.
     */
    error SignerAlreadyPresent(uint8 index);

    /**
     * @notice Thrown when same signer is used for signature verification.
     * @param index Index of duplicate signer.
     */
    error DuplicateSigner(uint8 index);

    /* -------------------------------------------------------------------------- */
    /*                                  FUNCTIONS                                 */
    /* -------------------------------------------------------------------------- */

    /// @notice Get signer at index from storage.
    function getSigner(MultiSigner storage $_, uint8 index_) internal view returns (Signer memory) {
        return $_.signers[index_];
    }

    /// @notice Get threshold from storage.
    function getThreshold(MultiSigner storage $_) internal view returns (uint8) {
        return $_.threshold;
    }

    /// @notice Get number of signers from storage.
    function getSignerCount(MultiSigner storage $_) internal view returns (uint8) {
        return $_.signerCount;
    }

    /**
     * @notice Adds signer at index in storage.
     *
     * @dev Throws error when a signer is already present at index.
     * @dev Throws error when signer is not EOA or Passkey.
     *
     * @param $_ Multi signer storage reference.
     * @param signer_ Signer to be set.
     * @param index_ Index to set signer at.
     */
    function addSigner(MultiSigner storage $_, Signer calldata signer_, uint8 index_) internal {
        if (!$_.signers[index_].isEmptyMem()) revert SignerAlreadyPresent(index_);

        _addSigner($_, signer_, index_);

        $_.signerCount = $_.signerCount + 1;
    }

    /**
     * @notice Removes signer at the given `index`.
     *
     * @dev Reverts if 'threshold' is equal to signer count.
     * @dev Reverts if signer is empty at `index`.
     *
     * @param $_ Multi signer storage reference.
     * @param index_ The index of the signer to be removed.
     * @return signer Signer being removed.
     */
    function removeSigner(MultiSigner storage $_, uint8 index_) internal returns (Signer memory signer) {
        uint8 signerCount = $_.signerCount;

        if (signerCount == $_.threshold) revert InvalidThreshold();

        signer = $_.signers[index_];

        if (signer.isEmptyMem()) revert SignerNotPresent(index_);

        delete $_.signers[index_];
        $_.signerCount = signerCount - 1;
    }

    /**
     * @notice Updates threshold of the signer set.
     *
     * @dev Reverts if 'threshold' is greater than signer count.
     * @dev Reverts if 'threshold' is 0.
     *
     * @param $_ Multi signer storage reference.
     * @param threshold_ The new signer set threshold.
     */
    function updateThreshold(MultiSigner storage $_, uint8 threshold_) internal {
        if (threshold_ == 0) revert InvalidThreshold();

        if ($_.signerCount < threshold_) revert InvalidThreshold();

        $_.threshold = threshold_;
    }

    /**
     * @notice Initialize the signers.
     *
     * @dev Intended to be called when initializing the signer set.
     * @dev Reverts if signer is neither an EOA or a passkey.
     * @dev Reverts if 'threshold' is less than number of signers.
     * @dev Reverts if 'threshold' is 0.
     * @dev Reverts if number of signers is more than 256.
     *
     * @param signers_ The initial set of signers.
     * @param threshold_ The number of signers needed for approval.
     */
    function initializeSigners(MultiSigner storage $_, Signer[] calldata signers_, uint8 threshold_) internal {
        if (signers_.length > type(uint8).max) revert InvalidNumberOfSigners();

        uint8 numSigners = uint8(signers_.length);

        if (numSigners < threshold_ || threshold_ < 1) revert InvalidThreshold();

        for (uint8 i; i < numSigners; i++) {
            _addSigner($_, signers_[i], i);
        }

        $_.signerCount = numSigners;
        $_.threshold = threshold_;
    }

    /// @dev reverts if signer is neither an EOA or a Passkey.
    /// @dev replaces signer at `index`. Should be used with proper checks.
    function _addSigner(MultiSigner storage $_, Signer calldata signer_, uint8 index_) private {
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

    /* -------------------------------------------------------------------------- */
    /*                              VALIDATE SIGNERS                              */
    /* -------------------------------------------------------------------------- */

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
        if (signers_.length > type(uint8).max) revert InvalidNumberOfSigners();

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

    /* -------------------------------------------------------------------------- */
    /*                             VALIDATE SIGNATURES                            */
    /* -------------------------------------------------------------------------- */

    /**
     * @notice validates if `hash_` was signed by the signer set present in `$_`
     *
     * @param $_ Multi signer storage reference.
     * @param hash_ blob of data that needs to be verified.
     * @param signatures_ List of signatureWrapper.
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
     * @param $_ Multi signer storage reference.
     * @param frontHash_ blob of data that should be signed by all but the last signer.
     * @param backHash_ blob of data that should be signed by the last signer.
     * @param signatures_ List of signatureWrapper.
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

            if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

            if ($_.signers[signerIndex].isValidSignature(frontHash_, signatures_[i].signatureData)) {
                alreadySigned |= mask;
            } else {
                isValid = false;
            }
        }

        signerIndex = signatures_[i].signerIndex;
        mask = (1 << signerIndex);

        if (alreadySigned & mask != 0) revert DuplicateSigner(signerIndex);

        if ($_.signers[signerIndex].isValidSignature(backHash_, signatures_[i].signatureData)) {
            alreadySigned |= mask;
        } else {
            isValid = false;
        }
    }
}
