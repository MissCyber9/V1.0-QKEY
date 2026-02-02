// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {KeyRef} from "./KeysetTypes.sol";

enum OpType {
    ROTATION_PROPOSE,
    ROTATION_FINALIZE,

    RECOVERY_PROPOSE,
    RECOVERY_EXECUTE,

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

/// @notice Meta operation container for relayers / AA.
/// @dev payloadHash must equal keccak256(payload) for ops that carry payload bytes.
struct MetaOp {
    OpType opType;
    bytes payload; // typed payload for opType (empty allowed for some ops)
    bytes32 payloadHash; // keccak256(payload)
    uint256 nonce; // must match wallet nonce
    uint256 deadline; // unix timestamp
    KeyRef authKey; // key used for signature verification
    bytes signature; // signature over EIP-712 struct
}
