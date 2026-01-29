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
                                TYPES
    //////////////////////////////////////////////////////////////*/

    struct PendingOp {
        OpType opType;
        bytes32 payloadHash;
        uint64 executableAt;
        uint64 expiresAt;
        uint64 guardianEpoch;
        bool executed;
    }

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
        uint64 guardianEpoch;

        PendingOp pendingOp;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => WalletState) internal wallets;

    IAuthVerifier public immutable VERIFIER;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(IAuthVerifier verifier_)
        EIP712Ops("QKeyRotationV1", "1.0.0")
    {
        VERIFIER = verifier_;
    }

    /*//////////////////////////////////////////////////////////////
                        WALLET INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function initializeWallet(
        uint256 walletId,
        KeyRef[] calldata initialKeys,
        KeyRef[] calldata guardians,
        Policy calldata policy
    ) external {
        WalletState storage w = wallets[walletId];
        require(!w.initialized, "QKEY: already initialized");

        w.keysetHash = KeysetLib.hash(initialKeys);
        w.guardiansHash = KeysetLib.hash(guardians);

        w.policy = policy;
        w.policyHash = PolicyHash.wrap(keccak256(abi.encode(policy)));

        w.initialized = true;
        w.guardianEpoch = 1;
        w.windowStart = uint64(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                            ROTATION
    //////////////////////////////////////////////////////////////*/

    function proposeRotation(
        uint256 walletId,
        bytes32 newKeysetHash
    ) external {
        WalletState storage w = wallets[walletId];
        require(w.initialized, "QKEY: not initialized");
        require(!w.recoveryActive, "QKEY: recovery active");

        w.pendingOp = PendingOp({
            opType: OpType.ROTATE_KEY,
            payloadHash: newKeysetHash,
            executableAt: uint64(block.timestamp + w.policy.rotationDelay),
            expiresAt: uint64(block.timestamp + w.policy.rotationDelay + 1 days),
            guardianEpoch: w.guardianEpoch,
            executed: false
        });
    }

    function finalizeRotation(uint256 walletId) external {
        WalletState storage w = wallets[walletId];
        PendingOp storage op = w.pendingOp;

        require(op.opType == OpType.ROTATE_KEY, "QKEY: wrong op");
        require(!op.executed, "QKEY: executed");
        require(block.timestamp >= op.executableAt, "QKEY: too early");
        require(block.timestamp <= op.expiresAt, "QKEY: expired");

        if (block.timestamp > w.windowStart + w.policy.windowSeconds) {
            w.windowStart = uint64(block.timestamp);
            w.rotationsInWindow = 0;
        }

        require(
            w.rotationsInWindow < w.policy.maxRotationsPerWindow,
            "QKEY: rate limited"
        );

        require(
            block.timestamp >= w.lastFinalizeAt + w.policy.minFinalizeCooldown,
            "QKEY: finalize cooldown"
        );

        w.keysetHash = op.payloadHash;
        w.rotationsInWindow++;
        w.lastFinalizeAt = uint64(block.timestamp);
        op.executed = true;

        emit RotationExecuted(walletId, op.payloadHash, w.policyHash);
    }

    /*//////////////////////////////////////////////////////////////
                            RECOVERY
    //////////////////////////////////////////////////////////////*/

    function proposeRecovery(
        uint256 walletId,
        bytes32 recoveredKeysetHash
    ) external {
        WalletState storage w = wallets[walletId];
        require(w.initialized, "QKEY: not initialized");
        require(!w.recoveryActive, "QKEY: recovery active");
        require(block.timestamp >= w.recoveryCooldownUntil, "QKEY: recovery cooldown");

        w.pendingOp = PendingOp({
            opType: OpType.RECOVERY,
            payloadHash: recoveredKeysetHash,
            executableAt: uint64(block.timestamp + w.policy.recoveryDelay),
            expiresAt: uint64(block.timestamp + w.policy.recoveryDelay + 1 days),
            guardianEpoch: w.guardianEpoch,
            executed: false
        });

        w.recoveryActive = true;
    }

    function executeRecovery(uint256 walletId) external {
        WalletState storage w = wallets[walletId];
        PendingOp storage op = w.pendingOp;

        require(op.opType == OpType.RECOVERY, "QKEY: wrong op");
        require(!op.executed, "QKEY: executed");
        require(block.timestamp >= op.executableAt, "QKEY: too early");
        require(block.timestamp <= op.expiresAt, "QKEY: expired");
        require(op.guardianEpoch == w.guardianEpoch, "QKEY: epoch mismatch");

        w.keysetHash = op.payloadHash;
        w.guardianEpoch++;
        w.recoveryActive = false;
        w.recoveryCooldownUntil =
            uint64(block.timestamp + w.policy.recoveryCooldown);

        op.executed = true;

        emit RecoveryExecuted(walletId, op.payloadHash, w.policyHash);
    }

    /*//////////////////////////////////////////////////////////////
                            FREEZE
    //////////////////////////////////////////////////////////////*/

    function freeze(uint256 walletId, uint64 duration) external {
        WalletState storage w = wallets[walletId];
        require(duration <= w.policy.freezeMaxDuration, "QKEY: too long");

        uint64 until = uint64(block.timestamp + duration);
        if (until > w.frozenUntil) {
            w.frozenUntil = until;
        }

        emit WalletFrozen(walletId, w.frozenUntil);
    }

    function unfreeze(uint256 walletId) external {
        WalletState storage w = wallets[walletId];
        w.frozenUntil = 0;
        emit WalletUnfrozen(walletId);
    }
}
