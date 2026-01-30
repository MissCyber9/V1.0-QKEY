// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712Ops} from "../core/EIP712Ops.sol";
import {OpType} from "../core/OpTypes.sol";
import {KeyRef} from "../core/KeysetTypes.sol";
import {Policy, PolicyHash} from "../core/PolicyTypes.sol";
import {ReasonCodes} from "../core/ReasonCodes.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";

/// @notice QKeyRotation V1 (foundation). Minimal, testable, introspection-first.
/// @dev This file is intentionally kept small and auditable. Advanced flows (batch, bonds, full recovery)
///      can be layered once tooling allows array-heavy tests safely.
contract QKeyRotationV1 is EIP712Ops {
    /*//////////////////////////////////////////////////////////////
                                  TYPES
    //////////////////////////////////////////////////////////////*/

    struct PendingOp {
        bool exists;
        OpType opType;
        bytes32 payloadHash;
        uint64 executableAt;
        uint64 expiresAt;
        uint64 guardianEpoch;
        bool executed;
        bool cancelled;
    }

    struct WalletState {
        bool initialized;

        bytes32 ownerKeysetHash;
        bytes32 guardiansKeysetHash;

        Policy policy;
        PolicyHash policyHash;

        // key allowlists
        mapping(bytes32 => bool) ownerKeyAllowed;
        mapping(bytes32 => bool) guardianKeyAllowed;

        // freeze
        uint64 frozenUntil;

        // nonce
        uint256 nonce;

        // rotation limits
        uint64 windowStart;
        uint32 rotationsInWindow;
        uint64 lastFinalizeAt;

        // recovery anti-abuse
        bool recoveryActive;
        uint64 recoveryCooldownUntil;
        uint64 guardianEpoch;
    }

    /*//////////////////////////////////////////////////////////////
                                  STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => WalletState) internal wallets;
    mapping(bytes32 => PendingOp) internal ops;

    IAuthVerifier public immutable VERIFIER;

    /*//////////////////////////////////////////////////////////////
                                  CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant METAOP_TYPEHASH = keccak256(
        "MetaOp(uint8 opType,bytes32 payloadHash,uint256 nonce,uint256 deadline,uint256 walletId,bytes32 opId,bytes32 authKeyId)"
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Raised when a dev-only function is called on a non-dev chain.
    error DevOnly();

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(IAuthVerifier verifier_) EIP712Ops("QKeyRotationV1", "1.0.0") {
        VERIFIER = verifier_;
    }

    function domainSeparator() external view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    /*//////////////////////////////////////////////////////////////
                          KEY IDS & HELPERS
    //////////////////////////////////////////////////////////////*/

    function keyId(KeyRef calldata k) public pure returns (bytes32) {
        return keccak256(abi.encode(k.scheme, keccak256(k.pubkey)));
    }

    function guardianKeyId(uint64 epoch, KeyRef calldata k) public pure returns (bytes32) {
        return keccak256(abi.encode(epoch, k.scheme, keccak256(k.pubkey)));
    }

    function _policyHash(Policy calldata p) internal pure returns (PolicyHash) {
        // Keep it stable + cheap. If Policy struct evolves, this hash changes intentionally.
        // Cast to PolicyHash for type safety.
        return PolicyHash.wrap(keccak256(abi.encode(p)));
    }

    /// @dev Canonical single-key keyset hash (forward-stable).
    /// For single-key sets, we commit (count=1, keyId).
    function _singleKeysetHash(KeyRef calldata k) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(1), keyId(k)));
    }

    /*//////////////////////////////////////////////////////////////
                         WALLET-LEVEL INTROSPECTION
    //////////////////////////////////////////////////////////////*/

    /// @notice Wallet-level introspection that does not depend on op existence.
    function explainWalletStatus(uint256 walletId) external view returns (uint256 reasons) {
        WalletState storage w = wallets[walletId];
        if (!w.initialized) reasons |= ReasonCodes.NOT_INITIALIZED;
        if (w.frozenUntil != 0 && block.timestamp < w.frozenUntil) {
            reasons |= ReasonCodes.FROZEN;
        }
    }

    /// @notice Explain why an operation (identified by opId) cannot be executed right now.
    /// Reasons are a stable bitmask (see ReasonCodes).
    function explainBlockers(uint256 walletId, bytes32 opId) public view returns (uint256 reasons) {
        reasons = this.explainWalletStatus(walletId);
        if (reasons != ReasonCodes.OK) {
            return reasons;
        }

        if (opId == bytes32(0)) {
            return ReasonCodes.BAD_PAYLOAD;
        }

        // Op registry exists (ops mapping), but higher-level ops wiring will be layered next.
        PendingOp storage op = ops[opId];
        if (!op.exists) return ReasonCodes.UNKNOWN_OP_ID;
        if (op.cancelled || op.executed) return ReasonCodes.ALREADY_EXECUTED;

        // basic time gates
        if (block.timestamp < op.executableAt) return ReasonCodes.TOO_EARLY;
        if (op.expiresAt != 0 && block.timestamp > op.expiresAt) return ReasonCodes.EXPIRED;

        return ReasonCodes.OK;
    }

    /// @notice Whether an op can be executed now, plus reason bitmask if not.
    function canExecute(uint256 walletId, bytes32 opId) external view returns (bool ok, uint256 reasons) {
        reasons = explainBlockers(walletId, opId);
        ok = (reasons == ReasonCodes.OK);
    }

    /// @notice Optional: whether a given actor can propose an op type (wallet-level only for now).
    function canPropose(
        uint256 walletId,
        uint8,
        /*opType*/
        address actor
    )
        external
        view
        returns (bool ok, uint256 reasons)
    {
        reasons = this.explainWalletStatus(walletId);
        if (reasons != ReasonCodes.OK) return (false, reasons);
        if (actor == address(0)) return (false, ReasonCodes.UNAUTHORIZED_ACTOR);
        return (true, ReasonCodes.OK);
    }

    /*//////////////////////////////////////////////////////////////
                      DEV-ONLY INITIALIZATION (NO ARRAYS)
    //////////////////////////////////////////////////////////////*/

    /// @dev DEV-ONLY initializer to avoid arrays in local Foundry tests.
    /// Gated by chainid==31337. Never use on production networks.
    function initializeWalletSingle(
        uint256 walletId,
        KeyRef calldata owner,
        KeyRef calldata guardian,
        Policy calldata policy
    ) external {
        if (block.chainid != 31337) revert DevOnly();

        WalletState storage w = wallets[walletId];
        if (w.initialized) revert("QKEY: already initialized");

        // keyset hashes (single-key canonical)
        w.ownerKeysetHash = _singleKeysetHash(owner);
        w.guardiansKeysetHash = _singleKeysetHash(guardian);

        // policy + snapshot hash
        w.policy = policy;
        w.policyHash = _policyHash(policy);

        // allowlists (owner by keyId; guardians by epoch-bound id)
        bytes32 ownerId = keyId(owner);
        w.ownerKeyAllowed[ownerId] = true;

        w.guardianEpoch = 0;
        bytes32 gId = guardianKeyId(0, guardian);
        w.guardianKeyAllowed[gId] = true;

        // housekeeping / limits
        w.initialized = true;
        w.frozenUntil = 0;
        w.nonce = 0;

        w.windowStart = uint64(block.timestamp);
        w.rotationsInWindow = 0;
        w.lastFinalizeAt = 0;

        w.recoveryActive = false;
        w.recoveryCooldownUntil = 0;
    }

    /*//////////////////////////////////////////////////////////////
                     RECOVERY ANTI-ABUSE (V1.0 CORE)
    //////////////////////////////////////////////////////////////*/

    function _recoveryPreProposeChecks(WalletState storage w) internal view returns (uint256 reasons) {
        if (!w.initialized) return ReasonCodes.NOT_INITIALIZED;
        if (w.recoveryActive) return ReasonCodes.RECOVERY_ACTIVE;
        if (w.recoveryCooldownUntil != 0 && block.timestamp < w.recoveryCooldownUntil) return ReasonCodes.COOLDOWN;
        return ReasonCodes.OK;
    }

    function _recoveryMarkProposed(WalletState storage w) internal {
        w.recoveryActive = true;
    }

    function _recoveryMarkExecuted(WalletState storage w) internal {
        w.recoveryActive = false;
        uint64 cd = w.policy.recoveryCooldown;
        if (cd != 0) w.recoveryCooldownUntil = uint64(block.timestamp) + cd;
        else w.recoveryCooldownUntil = 0;
    }

    /// @dev DEV-ONLY: create a recovery op in storage without signatures/arrays.
    /// This unblocks invariant/unit testing of anti-abuse rules.
    function devCreateRecoveryOp(
        uint256 walletId,
        bytes32 opId,
        bytes32 payloadHash,
        uint64 executableAt,
        uint64 expiresAt
    ) external {
        if (block.chainid != 31337) revert DevOnly();
        WalletState storage w = wallets[walletId];

        uint256 r = _recoveryPreProposeChecks(w);
        if (r != ReasonCodes.OK) revert("QKEY: recovery propose blocked");

        PendingOp storage op = ops[opId];
        if (op.exists) revert("QKEY: op exists");

        op.exists = true;
        op.opType = OpType.RECOVERY_PROPOSE;
        op.payloadHash = payloadHash;
        op.executableAt = executableAt;
        op.expiresAt = expiresAt;
        op.guardianEpoch = w.guardianEpoch;
        op.executed = false;
        op.cancelled = false;

        _recoveryMarkProposed(w);
    }

    /// @dev DEV-ONLY: mark a recovery op executed (simulates executeRecovery success) and applies cooldown.
    function devExecuteRecovery(uint256 walletId, bytes32 opId) external {
        if (block.chainid != 31337) revert DevOnly();
        WalletState storage w = wallets[walletId];

        PendingOp storage op = ops[opId];
        if (!op.exists) revert("QKEY: unknown op");
        if (op.executed || op.cancelled) revert("QKEY: already finalized");
        if (op.opType != OpType.RECOVERY_PROPOSE && op.opType != OpType.RECOVERY_EXECUTE) {
            revert("QKEY: wrong op type");
        }

        // time checks (mirrors explainBlockers)
        if (block.timestamp < op.executableAt) revert("QKEY: too early");
        if (op.expiresAt != 0 && block.timestamp > op.expiresAt) revert("QKEY: expired");

        op.executed = true;
        _recoveryMarkExecuted(w);
    }

    /// @dev DEV-ONLY owner veto for contestable recovery. Gated by chainid==31337.
    function vetoRecovery(uint256 walletId, bytes32 opId) external {
        if (block.chainid != 31337) revert DevOnly();

        WalletState storage w = wallets[walletId];
        if (!w.initialized) revert("QKEY: not initialized");

        PendingOp storage op = ops[opId];
        if (!op.exists) revert("QKEY: unknown op");
        if (op.executed || op.cancelled) revert("QKEY: already finalized");
        if (op.opType != OpType.RECOVERY_PROPOSE && op.opType != OpType.RECOVERY_EXECUTE) {
            revert("QKEY: wrong op type");
        }

        if (!w.policy.contestableRecovery) revert("QKEY: contest disabled");

        if (w.policy.vetoRequiresNotFrozen) {
            if (w.frozenUntil != 0 && block.timestamp < w.frozenUntil) revert("QKEY: veto blocked when frozen");
        }

        uint64 win = w.policy.ownerVetoWindow;
        if (win != 0) {
            if (block.timestamp > uint256(op.executableAt) + uint256(win)) revert("QKEY: veto window passed");
        }

        op.cancelled = true;
        w.recoveryActive = false;
    }
}
