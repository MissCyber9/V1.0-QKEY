// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

abstract contract EIP712Ops {
    bytes32 internal immutable DOMAIN_SEPARATOR;

    constructor(string memory name, string memory version) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    function _opDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
    }
}
