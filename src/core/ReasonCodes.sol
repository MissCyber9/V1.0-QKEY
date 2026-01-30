// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Stable reason codes bitmask for QKeyRotation V1.
/// Each bit set means a blocker is active.
/// SDKs should decode by testing (reasons & CODE) != 0.
library ReasonCodes {
    // Wallet / general
    uint256 internal constant NONE = 0;
    uint256 internal constant OK = NONE; // backward-compatible alias
    uint256 internal constant NOT_INITIALIZED = 1 << 0;
    uint256 internal constant FROZEN = 1 << 1;

    // Execution / scheduling
    uint256 internal constant COOLDOWN = 1 << 2;
    uint256 internal constant RATE_LIMITED = 1 << 3;
    uint256 internal constant TOO_EARLY = 1 << 4;
    uint256 internal constant EXPIRED = 1 << 5;

    // Recovery / epochs
    uint256 internal constant EPOCH_MISMATCH = 1 << 6;

    // Auth / payload
    uint256 internal constant UNAUTHORIZED_ACTOR = 1 << 7;
    uint256 internal constant BAD_PAYLOAD = 1 << 8;
    uint256 internal constant INSUFFICIENT_APPROVALS = 1 << 9;

    // Op lifecycle
    uint256 internal constant ALREADY_EXECUTED = 1 << 10;
    uint256 internal constant WRONG_OP_TYPE = 1 << 11;
    uint256 internal constant POLICY_DISABLED = 1 << 12;
    uint256 internal constant UNKNOWN_OP_ID = 1 << 13;
    uint256 internal constant NONCE_MISMATCH = 1 << 14;
    uint256 internal constant RECOVERY_ACTIVE = 1 << 15;
}
