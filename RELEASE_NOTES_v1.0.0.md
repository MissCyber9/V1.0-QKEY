# QKeyRotationV1 — v1.0.0

## What’s included
- Stable introspection API returning reason-code bitmasks.
- Wallet status explainers (not initialized / frozen).
- Recovery anti-abuse: one-active + cooldown.
- Typed blockers coverage (epoch mismatch, wrong op type, too early, expired, unknown op).

## What’s intentionally NOT included in this public cut
- Owner veto recovery path (removed during stabilization).
- MetaOp batching (to be reintroduced as v1.1 with clean surface + tests).
- Anti-spam bond economics (premium module, later).
