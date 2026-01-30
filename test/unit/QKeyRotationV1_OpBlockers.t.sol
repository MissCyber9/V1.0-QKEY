// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";
import {KeyRef} from "../../src/core/KeysetTypes.sol";
import {Policy} from "../../src/core/PolicyTypes.sol";
import {ReasonCodes} from "../../src/core/ReasonCodes.sol";

contract QKeyRotationV1_OpBlockers is Test {
    function _key(address a) internal pure returns (KeyRef memory k) {
        k.scheme = 0;
        k.pubkey = abi.encodePacked(bytes20(a));
    }

    function _policy() internal pure returns (Policy memory p) {
        p.rotationDelay = 1 hours;
        p.recoveryDelay = 2 hours;
        p.freezeMaxDuration = 7 days;
        p.windowSeconds = 1 days;
        p.maxRotationsPerWindow = 3;
        p.minFinalizeCooldown = 10 minutes;

        p.recoveryCooldown = 1 days;
        p.contestableRecovery = true;
    }

    function test_blockers_unknown_op() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        uint256 r = q.explainBlockers(1, keccak256("nope"));
        assertEq(r, ReasonCodes.UNKNOWN_OP_ID);
    }

    function test_blockers_too_early() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        bytes32 opId = keccak256("op");
        q.devCreateRecoveryOp(1, opId, keccak256("p"), uint64(block.timestamp + 10), 0);

        uint256 r = q.explainBlockers(1, opId);
        assertEq(r, ReasonCodes.TOO_EARLY);
    }

    function test_blockers_expired() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        bytes32 opId = keccak256("op");
        q.devCreateRecoveryOp(1, opId, keccak256("p"), uint64(block.timestamp), uint64(block.timestamp + 5));
        vm.warp(block.timestamp + 6);

        uint256 r = q.explainBlockers(1, opId);
        assertEq(r, ReasonCodes.EXPIRED);
    }
}
