# QKeyRotationV1 – Stable Release (v1.0.0)

QKeyRotationV1 is a production-ready key-rotation and recovery engine designed for
high-security wallets and secure applications (e.g. CarthEdge).

---

## Status

- ✅ All unit tests passing
- ✅ CI green
- ✅ Recovery anti-abuse (one-active, cooldown, veto window)
- ✅ Introspection APIs (explainBlockers, explainWalletStatus)
- ✅ Guardian epoch safety
- ✅ EIP-712 domain separation
- ✅ Public, stable API

---

## Core Capabilities

- Deterministic key rotation
- Guardian-based recovery
- Recovery veto and cooldown
- Explicit wallet and operation introspection
- Replay, griefing, and abuse resistance

---

## Stable Public API (v1.0.0)

- initializeWalletSingle
- canPropose
- canExecute
- explainBlockers
- explainWalletStatus

⚠️ API is considered stable starting from v1.0.0.

---

## Threat Model (Covered)

- Guardian key compromise
- Stale / replayed operations
- Recovery abuse and griefing
- Unauthorized execution
- Epoch desynchronization

---

## Integration

QKeyRotationV1 is designed to be embedded by higher-level applications.
It does not manage UI, transport, or identity by itself.

Reference integration:
→ **CarthEdge** (secure Web3 communication platform)

---

## Security Notes

- Core logic is immutable once deployed
- Do not fork or modify without understanding invariants
- All recovery logic is intentionally explicit and introspectable

---

## License

MIT
