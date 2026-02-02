// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712Ops} from "../core/EIP712Ops.sol";
import {OpType} from "../core/OpTypes.sol";
import {KeyRef} from "../core/KeysetTypes.sol";
import {Policy, PolicyHash} from "../core/PolicyTypes.sol";
import {ReasonCodes} from "../core/ReasonCodes.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";

contract QKeyRotationV1 is EIP712Ops {
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

        mapping(bytes32 => bool) ownerKeyAllowed;
        mapping(bytes32 => bool) guardianKeyAllowed;

        uint64 frozenUntil;

        uint256 nonce;

        uint64 windowStart;
        uint32 rotationsInWindow;
        uint64 lastFinalizeAt;

        bool recoveryActive;
        uint64 recoveryCooldownUntil;
        uint64 guardianEpoch;
    }

    mapping(uint256 => WalletState) internal wallets;
    mapping(bytes32 => PendingOp) internal ops;

    IAuthVerifier public immutable VERIFIER;

    error DevOnly();

    bytes32 internal constant METAOP_TYPEHASH = keccak256(
        "MetaOp(uint8 opType,bytes32 payloadHash,uint256 nonce,uint256 deadline,uint256 walletId,bytes32 opId,bytes32 authKeyId)"
    );

    constructor(IAuthVerifier verifier_) EIP712Ops("QKeyRotationV1", "1.0.0") {
        VERIFIER = verifier_;
    }

    function domainSeparator() external view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    function keyId(KeyRef calldata k) public pure returns (bytes32) {
        return keccak256(abi.encode(k.scheme, keccak256(k.pubkey)));
    }

    function guardianKeyId(uint64 epoch, KeyRef calldata k) public pure returns (bytes32) {
        return keccak256(abi.encode(epoch, k.scheme, keccak256(k.pubkey)));
    }

    function _policyHash(Policy calldata p) internal pure returns (PolicyHash) {
        return PolicyHash.wrap(keccak256(abi.encode(p)));
    }

    function _singleKeysetHash(KeyRef calldata k) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(1), keyId(k)));
    }

    function explainWalletStatus(uint256 walletId) external view returns (uint256 reasons) {
        WalletState storage w = wallets[walletId];
        if (!w.initialized) reasons |= ReasonCodes.NOT_INITIALIZED;
        if (w.frozenUntil != 0 && block.timestamp < w.frozenUntil) reasons |= ReasonCodes.FROZEN;
    }

    function explainBlockers(uint256 walletId, bytes32 opId) public view returns (uint256 reasons) {
        reasons = this.explainWalletStatus(walletId);
        if (reasons != ReasonCodes.OK) return reasons;

        if (opId == bytes32(0)) return ReasonCodes.BAD_PAYLOAD;

        PendingOp storage op = ops[opId];
        if (!op.exists) return ReasonCodes.UNKNOWN_OP_ID;
        if (op.guardianEpoch != wallets[walletId].guardianEpoch) return ReasonCodes.EPOCH_MISMATCH;
        if (op.cancelled || op.executed) return ReasonCodes.ALREADY_EXECUTED;

        if (block.timestamp < op.executableAt) return ReasonCodes.TOO_EARLY;
        if (op.expiresAt != 0 && block.timestamp > op.expiresAt) return ReasonCodes.EXPIRED;

        return ReasonCodes.OK;
    }

    function canExecute(uint256 walletId, bytes32 opId) external view returns (bool ok, uint256 reasons) {
        reasons = explainBlockers(walletId, opId);
        ok = (reasons == ReasonCodes.OK);
    }

    function explainBlockersTyped(uint256 walletId, bytes32 opId, OpType expectedOpType)
        external
        view
        returns (uint256 reasons)
    {
        reasons = this.explainBlockers(walletId, opId);
        if (reasons != ReasonCodes.OK) return reasons;

        PendingOp storage op = ops[opId];
        // op exists already (otherwise explainBlockers returns UNKNOWN_OP_ID)
        if (op.opType != expectedOpType) return ReasonCodes.WRONG_OP_TYPE;

        return ReasonCodes.OK;
    }

    function canExecuteTyped(uint256 walletId, bytes32 opId, OpType expectedOpType)
        external
        view
        returns (bool ok, uint256 reasons)
    {
        reasons = this.explainBlockersTyped(walletId, opId, expectedOpType);
        ok = (reasons == ReasonCodes.OK);
    }

    function canPropose(uint256 walletId, uint8, address actor) external view returns (bool ok, uint256 reasons) {
        reasons = this.explainWalletStatus(walletId);
        if (reasons != ReasonCodes.OK) return (false, reasons);
        if (actor == address(0)) return (false, ReasonCodes.UNAUTHORIZED_ACTOR);
        return (true, ReasonCodes.OK);
    }

    function initializeWalletSingle(
        uint256 walletId,
        KeyRef calldata owner,
        KeyRef calldata guardian,
        Policy calldata policy
    ) external {
        if (block.chainid != 31337) revert DevOnly();
        WalletState storage w = wallets[walletId];
        if (w.initialized) revert("QKEY: already initialized");

        w.ownerKeysetHash = _singleKeysetHash(owner);
        w.guardiansKeysetHash = _singleKeysetHash(guardian);

        w.policy = policy;
        w.policyHash = _policyHash(policy);

        w.ownerKeyAllowed[keyId(owner)] = true;

        w.guardianEpoch = 0;
        w.guardianKeyAllowed[guardianKeyId(0, guardian)] = true;

        w.initialized = true;
        w.windowStart = uint64(block.timestamp);
    }

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
        w.recoveryCooldownUntil = (cd != 0) ? uint64(block.timestamp) + cd : 0;
    }

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

        _recoveryMarkProposed(w);
    }

    function devExecuteRecovery(uint256 walletId, bytes32 opId) external {
        if (block.chainid != 31337) revert DevOnly();
        WalletState storage w = wallets[walletId];

        PendingOp storage op = ops[opId];
        if (!op.exists) revert("QKEY: unknown op");
        if (op.executed || op.cancelled) revert("QKEY: already finalized");
        if (block.timestamp < op.executableAt) revert("QKEY: too early");
        if (op.expiresAt != 0 && block.timestamp > op.expiresAt) revert("QKEY: expired");

        op.executed = true;
        _recoveryMarkExecuted(w);
        unchecked {
            w.guardianEpoch += 1;
        }
    }

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
        if (w.frozenUntil != 0 && block.timestamp < w.frozenUntil) revert("QKEY: veto blocked when frozen");

        op.cancelled = true;
        w.recoveryActive = false;
    }

    // ===== Public Recovery API (devchain-only wrappers) =====
}
