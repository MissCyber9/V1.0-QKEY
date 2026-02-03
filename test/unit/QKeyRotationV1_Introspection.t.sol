// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";
import {ReasonCodes} from "../../src/core/ReasonCodes.sol";

contract QKeyRotationV1_Introspection is Test {
    function test_canExecute_not_initialized() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier(), true);
        (bool ok, uint256 reasons) = q.canExecute(1, bytes32(uint256(1)));

        assertTrue(!ok);
        assertTrue((reasons & ReasonCodes.NOT_INITIALIZED) != 0);
    }

    function test_explainBlockers_bad_opid_zero() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier(), true);
        // wallet not initialized dominates, so we must observe NOT_INITIALIZED still set
        uint256 reasons = q.explainBlockers(1, bytes32(0));
        assertTrue((reasons & ReasonCodes.NOT_INITIALIZED) != 0);
    }

    function test_canPropose_actor_zero_rejected() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier(), true);
        // wallet not initialized dominates, so NOT_INITIALIZED expected
        (bool ok, uint256 reasons) = q.canPropose(1, 0, address(0));
        assertTrue(!ok);
        assertTrue((reasons & ReasonCodes.NOT_INITIALIZED) != 0);
    }
}
