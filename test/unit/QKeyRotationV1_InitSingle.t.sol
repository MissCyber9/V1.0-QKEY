// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";

import {KeyRef} from "../../src/core/KeysetTypes.sol";
import {Policy} from "../../src/core/PolicyTypes.sol";
import {ReasonCodes} from "../../src/core/ReasonCodes.sol";

contract QKeyRotationV1_InitSingle is Test {
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
    }

    function test_initializeWalletSingle_clears_not_initialized_and_allows_canPropose() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier(), true);

        uint256 r0 = q.explainWalletStatus(1);
        assertTrue((r0 & ReasonCodes.NOT_INITIALIZED) != 0);

        q.initializeWalletSingle(1, _key(address(0x1111)), _key(address(0x2222)), _policy());

        uint256 r1 = q.explainWalletStatus(1);
        assertTrue((r1 & ReasonCodes.NOT_INITIALIZED) == 0);

        (bool ok, uint256 reasons) = q.canPropose(1, 0, address(0xBEEF));
        assertTrue(ok);
        assertEq(reasons, ReasonCodes.OK);
    }
}
