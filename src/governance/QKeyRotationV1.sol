// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Policy, PolicyHash} from "../core/PolicyTypes.sol";
import {ReasonCodes} from "../core/ReasonCodes.sol";
import {KeyRef} from "../core/KeysetTypes.sol";
import {KeysetLib} from "../libraries/KeysetLib.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";
import {EIP712Ops} from "../core/EIP712Ops.sol";
import {MetaOp, OpType, BatchMode} from "../core/OpTypes.sol";

contract QKeyRotationV1 is EIP712Ops {
    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RotationExecuted(
        uint256 indexed walletId,
        bytes32 newKeysetHash,
        PolicyHash policyHashSnapshot
    );

    event RecoveryExecuted(
        uint256 indexed walletId,
        bytes32 recoveredKeysetHash,
        PolicyHash policyHashSnapshot
    );

    event GuardiansUpdated(
        uint256 indexed walletId,
        bytes32 guardiansHash,
        PolicyHash policyHashSnapshot
    );

    event WalletFrozen(uint256 indexed walletId, uint64 until);
    event WalletUnfrozen(uint256 indexed walletId);

    event BatchResult(
        uint256 indexed walletId,
        uint256 indexed index,
        OpType opType,
        bool success,
        uint256 reasonCodes
    );

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    struct WalletState {
        bool initialized;

        bytes32 keysetHash;
        bytes32 guardiansHash;

        Policy policy;
        PolicyHash policyHash;

        uint64 frozenUntil;

        uint256 nonce;

        // rotation rate limit
        uint64 windowStart;
        uint32 rotationsInWindow;
        uint64 lastFinalizeAt;

        // recovery anti-abuse
        bool recoveryActive;
        uint64 recoveryCooldownUntil;
    }

    mapping(uint256 => WalletState) internal wallets;

    IAuthVerifier public immutable verifier;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(IAuthVerifier _verifier)
        EIP712Ops("QKeyRotationV1", "1.0.0")
    {
        verifier = _verifier;
    }

    /*//////////////////////////////////////////////////////////////
                        INTROSPECTION (CORE)
    //////////////////////////////////////////////////////////////*/

    function canExecute(
        uint256 walletId,
        bytes32 /*opId*/
    ) external view returns (bool ok, uint256 reasons) {
        reasons = _computeBlockers(walletId);
        ok = (reasons == ReasonCodes.OK);
    }

    function explainBlockers(
        uint256 walletId,
        bytes32 /*opId*/
    ) external view returns (uint256 reasons) {
        return _computeBlockers(walletId);
    }

    function canPropose(
        uint256 walletId,
        OpType /*opType*/,
        address /*actor*/
    ) external view returns (bool ok, uint256 reasons) {
        WalletState storage w = wallets[walletId];
        if (!w.initialized) {
            reasons |= ReasonCodes.NOT_INITIALIZED;
        }
        if (_isFrozen(w)) {
            reasons |= ReasonCodes.FROZEN;
        }
        ok = (reasons == 0);
    }

    function _computeBlockers(uint256 walletId)
        internal
        view
        returns (uint256 reasons)
    {
        WalletState storage w = wallets[walletId];

        if (!w.initialized) {
            reasons |= ReasonCodes.NOT_INITIALIZED;
        }
        if (_isFrozen(w)) {
            reasons |= ReasonCodes.FROZEN;
        }
        if (w.recoveryActive) {
            reasons |= ReasonCodes.RECOVERY_IN_PROGRESS;
        }
        if (block.timestamp < w.recoveryCooldownUntil) {
            reasons |= ReasonCodes.RECOVERY_COOLDOWN;
        }
    }

    function _isFrozen(WalletState storage w) internal view returns (bool) {
        return w.frozenUntil != 0 && block.timestamp < w.frozenUntil;
    }

    /*//////////////////////////////////////////////////////////////
                          META / BATCH EXECUTION
    //////////////////////////////////////////////////////////////*/

    function executeBatch(
        uint256 walletId,
        MetaOp[] calldata ops,
        BatchMode mode
    ) external returns (uint256[] memory reasonsPerOp) {
        reasonsPerOp = new uint256[](ops.length);

        for (uint256 i = 0; i < ops.length; i++) {
            uint256 reasons = _executeMetaOp(walletId, ops[i]);
            reasonsPerOp[i] = reasons;

            emit BatchResult(
                walletId,
                i,
                ops[i].opType,
                reasons == ReasonCodes.OK,
                reasons
            );

            if (mode == BatchMode.ATOMIC && reasons != ReasonCodes.OK) {
                revert("QKEY: atomic batch failed");
            }
        }
    }

    function _executeMetaOp(
        uint256 walletId,
        MetaOp calldata op
    ) internal returns (uint256 reasons) {
        WalletState storage w = wallets[walletId];

        // global blockers
        reasons |= _computeBlockers(walletId);
        if (reasons != 0) return reasons;

        if (op.deadline < block.timestamp) {
            return ReasonCodes.EXPIRED;
        }

        if (op.nonce != w.nonce) {
            return ReasonCodes.NONCE_MISMATCH;
        }

        // NOTE: payload execution deferred to later phases
        // Here we only consume nonce + signal success

        w.nonce++;

        return ReasonCodes.OK;
    }
}
