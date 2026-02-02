// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Key reference used across all auth systems
struct KeyRef {
    uint8 scheme; // 0 = ECDSA, future values reserved
    bytes pubkey; // raw public key bytes
}
