# Changelog

All notable changes are documented here. The format follows Keep a Changelog;
the project uses Semantic Versioning.

## [Unreleased]

## [0.1.0a1] - 2026-07-12

### Added

- Role-separated issuer and verifier credentials.
- Opaque 256-bit proofs bound to client, subject, purpose, audience, and expiry.
- Atomic single-use verification with durable replay rejection.
- Canonical verifier idempotency with a documented 24-hour minimum retention.
- Client, credential, and root hash-key rotation and revocation gates.
- Durable credential pre-delivery, paired database/keyring backup, and
  enforced single-server/root-key lifecycle locks.
- Recovery-sealed backups that revoke snapshot authority before restored
  readiness, plus KID-to-key-material compatibility checks.
- Durable per-client-role quotas that survive credential rotation.
- SQLite persistence without raw proofs or credentials.
- Boundary receipts and verification witnesses backed by OpenAPI 3.1.
- Loopback-only configuration, operational container bootstrap, CLI,
  health/readiness, and operations guidance.

[Unreleased]: https://github.com/HOLYAC/onceproof/compare/v0.1.0a1...HEAD
[0.1.0a1]: https://github.com/HOLYAC/onceproof/releases/tag/v0.1.0a1
