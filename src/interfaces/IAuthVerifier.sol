// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {KeyRef} from "../core/KeysetTypes.sol";

/// @title IAuthVerifier
/// @notice Interface boundary for signature verification (ECDSA today, PQ tomorrow)
interface IAuthVerifier {
    function verify(
        bytes32 digest,
        bytes calldata sig,
        KeyRef calldata key
    ) external view returns (bool);
}
