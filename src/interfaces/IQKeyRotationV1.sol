pragma solidity ^0.8.24;

import {KeyRef} from "../core/KeysetTypes.sol";
import {Policy} from "../core/PolicyTypes.sol";
import {OpType, BatchMode, MetaOp} from "../core/OpTypes.sol";

interface IQKeyRotationV1 {
    // EIP-712
    function domainSeparator() external view returns (bytes32);

    // Init (minimal)
    function initializeWalletSingle(
        uint256 walletId,
        KeyRef calldata owner,
        KeyRef calldata guardian,
        Policy calldata policy
    ) external;

    // Introspection helpers (pour intégration app)
    function explainWalletStatus(uint256 walletId) external view returns (uint256 reasons);
    function explainBlockers(uint256 walletId, bytes32 opId) external view returns (uint256 reasons);
    function canPropose(uint256 walletId, OpType opType, address actor) external view returns (uint256 reasons);
    function canExecute(uint256 walletId, bytes32 opId) external view returns (uint256 reasons);

    // Batch exec (si exposé dans ton contrat)
    function executeBatch(uint256 walletId, MetaOp[] calldata ops, BatchMode mode)
        external
        returns (uint256[] memory reasons);
}
