// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";

import {KeyRef} from "../../src/core/KeysetTypes.sol";
import {Policy} from "../../src/core/PolicyTypes.sol";
import {ReasonCodes} from "../../src/core/ReasonCodes.sol";

contract QKeyRotationV1_RecoveryAntiAbuse is Test {
    function _key(address a) internal pure returns (KeyRef memory k) {
        k.scheme = 0;
        k.pubkey = abi.encodePacked(bytes20(a));
    }

    function _policy() internal pure returns (Policy memory p) {
        // existing v0.3 fields
        p.rotationDelay = 1 hours;
        p.recoveryDelay = 2 hours;
        p.freezeMaxDuration = 7 days;
        p.windowSeconds = 1 days;
        p.maxRotationsPerWindow = 3;
        p.minFinalizeCooldown = 10 minutes;

        // v1.0 recovery anti-abuse fields
        p.recoveryCooldown = 1 days;
        p.contestableRecovery = true;
    }

    function test_one_active_recovery_blocks_second() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        bytes32 op1 = keccak256("op1");
        bytes32 op2 = keccak256("op2");

        q.devCreateRecoveryOp(1, op1, keccak256("p1"), uint64(block.timestamp), 0);

        vm.expectRevert(bytes("QKEY: recovery propose blocked"));
        q.devCreateRecoveryOp(1, op2, keccak256("p2"), uint64(block.timestamp), 0);
    }

    function test_execute_sets_cooldown_blocks_new_recovery_until_passed() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        bytes32 op1 = keccak256("op1");
        q.devCreateRecoveryOp(1, op1, keccak256("p1"), uint64(block.timestamp), 0);

        q.devExecuteRecovery(1, op1);

        bytes32 op2 = keccak256("op2");
        vm.expectRevert(bytes("QKEY: recovery propose blocked"));
        q.devCreateRecoveryOp(1, op2, keccak256("p2"), uint64(block.timestamp), 0);

        vm.warp(block.timestamp + 1 days + 1);
        q.devCreateRecoveryOp(1, op2, keccak256("p2"), uint64(block.timestamp), 0);
    }

}
