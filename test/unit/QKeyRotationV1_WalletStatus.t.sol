// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {QKeyRotationV1} from "../../src/governance/QKeyRotationV1.sol";
import {ECDSAVerifier} from "../../src/verifiers/ECDSAVerifier.sol";
import {ReasonCodes} from "../../src/core/ReasonCodes.sol";

contract QKeyRotationV1_WalletStatus is Test {
    function test_explainWalletStatus_not_initialized() external {
        QKeyRotationV1 q = new QKeyRotationV1(new ECDSAVerifier());
        uint256 reasons = q.explainWalletStatus(1);

        assertTrue((reasons & ReasonCodes.NOT_INITIALIZED) != 0);
        assertTrue((reasons & ReasonCodes.FROZEN) == 0);
    }
}
