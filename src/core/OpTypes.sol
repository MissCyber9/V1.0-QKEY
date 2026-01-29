// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

enum OpType {
    ROTATE_KEY,
    RECOVERY,
    UPDATE_POLICY,
    UPDATE_GUARDIANS,
    FREEZE,
    UNFREEZE,
    CANCEL
}

enum BatchMode {
    ATOMIC,
    BEST_EFFORT
}

struct MetaOp {
    OpType opType;
    bytes32 payloadHash;
    uint256 nonce;
    uint256 deadline;
    bytes signature;
}
