// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {KeyRef} from "../core/KeysetTypes.sol";

library KeysetLib {
    error EmptyKeyset();

    /// @notice Canonical hash of a keyset (order-independent)
    function hash(KeyRef[] memory keys) internal pure returns (bytes32) {
        if (keys.length == 0) revert EmptyKeyset();

        // Sort keys in-place by (scheme, pubkey)
        _sort(keys);

        bytes32 h;
        for (uint256 i = 0; i < keys.length; i++) {
            h = keccak256(
                abi.encodePacked(
                    h,
                    keys[i].scheme,
                    keccak256(keys[i].pubkey)
                )
            );
        }
        return h;
    }

    function _sort(KeyRef[] memory a) private pure {
        uint256 n = a.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                if (_gt(a[i], a[j])) {
                    KeyRef memory tmp = a[i];
                    a[i] = a[j];
                    a[j] = tmp;
                }
            }
        }
    }

    function _gt(KeyRef memory x, KeyRef memory y) private pure returns (bool) {
        if (x.scheme != y.scheme) {
            return x.scheme > y.scheme;
        }
        return keccak256(x.pubkey) > keccak256(y.pubkey);
    }
}
