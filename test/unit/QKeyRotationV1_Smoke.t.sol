// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";

contract QKeyRotationV1_Smoke is Test {
    function test_deploy_and_domain_separator() external {
        ECDSAVerifier v = new ECDSAVerifier();
        QKeyRotationV1 q = new QKeyRotationV1(v, true);

        assertTrue(address(q) != address(0));

        bytes32 ds = q.domainSeparator();
        assertTrue(ds != bytes32(0));
    }
}
