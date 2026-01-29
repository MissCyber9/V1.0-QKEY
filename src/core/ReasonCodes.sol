// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReasonCodes
/// @notice Stable bitmask reason codes for introspection and batch execution
/// @dev DO NOT reorder or reuse bits once released
library ReasonCodes {
    uint256 internal constant OK                     = 0;

    uint256 internal constant NOT_INITIALIZED         = 1 << 0;
    uint256 internal constant FROZEN                  = 1 << 1;
    uint256 internal constant COOLDOWN                = 1 << 2;
    uint256 internal constant RATE_LIMITED            = 1 << 3;
    uint256 internal constant EPOCH_MISMATCH          = 1 << 4;
    uint256 internal constant TOO_EARLY               = 1 << 5;
    uint256 internal constant EXPIRED                 = 1 << 6;
    uint256 internal constant INSUFFICIENT_APPROVALS  = 1 << 7;
    uint256 internal constant ALREADY_EXECUTED        = 1 << 8;
    uint256 internal constant WRONG_OP_TYPE           = 1 << 9;
    uint256 internal constant UNAUTHORIZED_ACTOR      = 1 << 10;
    uint256 internal constant BAD_PAYLOAD             = 1 << 11;
    uint256 internal constant POLICY_DISABLED         = 1 << 12;
    uint256 internal constant UNKNOWN_OP_ID           = 1 << 13;
    uint256 internal constant NONCE_MISMATCH          = 1 << 14;
    uint256 internal constant BOND_REQUIRED           = 1 << 15;
    uint256 internal constant RECOVERY_IN_PROGRESS    = 1 << 16;
    uint256 internal constant RECOVERY_COOLDOWN       = 1 << 17;
    uint256 internal constant CONTEST_WINDOW_ACTIVE   = 1 << 18;
}
