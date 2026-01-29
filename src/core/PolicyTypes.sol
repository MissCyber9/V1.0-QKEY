// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Governance policy configuration for a wallet
struct Policy {
    uint64 rotationDelay;
    uint64 recoveryDelay;
    uint64 freezeMaxDuration;

    uint64 windowSeconds;
    uint32 maxRotationsPerWindow;
    uint64 minFinalizeCooldown;

    // Recovery anti-abuse
    uint64 recoveryCooldown;
    bool   contestableRecovery;
}

/// @notice Snapshot hash used for telemetry & audit trails
type PolicyHash is bytes32;
