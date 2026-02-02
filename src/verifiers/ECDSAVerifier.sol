// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IAuthVerifier} from "../interfaces/IAuthVerifier.sol";
import {KeyRef} from "../core/KeysetTypes.sol";

contract ECDSAVerifier is IAuthVerifier {
    function verify(bytes32 digest, bytes calldata sig, KeyRef calldata key) external pure returns (bool) {
        if (key.scheme != 0) return false;
        address signer = ECDSA.recover(digest, sig);
        return signer == address(bytes20(key.pubkey));
    }
}
