# Threat model

## Security claim

For one configured client on one SQLite-backed Onceproof instance, an
authenticated issuer can mint a short-lived opaque proof and an authenticated
verifier can consume that proof at most once for its bound subject, purpose,
and audience.

The claim does not include the truth of the issuer's evidence. Anyone holding
an issuer credential can mint proofs. Onceproof is therefore a transport and
replay boundary, not a trust oracle.

## Assets

- Raw `opi1` issuance credentials.
- Raw `opv1` verification credentials.
- Raw `op1` proofs before redemption.
- The root hash-key keyring.
- SQLite claim, consume, idempotency, and audit state.

## Trust boundaries

- Administrator to local CLI and keyring filesystem.
- Issuer to `POST /v1/proofs`.
- Holder transport between issuer and verifier.
- Verifier to `POST /v1/verifications`.
- Onceproof process to SQLite and the keyring file.
- TLS reverse proxy to the loopback Onceproof server.

## Defended threats

### Database disclosure

The database contains keyed HMAC digests, not raw proofs or credentials. An
attacker needs both database state and keyring material to validate guesses.
Proofs and credentials already contain 256 random bits, so offline guessing is
not a practical recovery path. The stored KID compatibility check is also an
offline verifier for a guessed 256-bit root key; it detects restore mistakes
without making exhaustive recovery practical.

### Replay

The consume update, verification record, and audit record share one SQLite
write transaction. A conditional update and concurrency test enforce one
winner. Exact transport retries require the original idempotency key and
request fingerprint.

### Cross-client substitution

Credential lookup determines the client. Proof lookup must match that client;
a proof owned by another client is returned as `invalid` and is not consumed.

### Context substitution

Purpose, audience, and subject are required exact-match bindings. Mismatch does
not consume.

### Secret role confusion

Issuer and verifier credentials have distinct prefixes, database roles, HTTP
paths, and authentication checks. One role cannot invoke the other command.

### False acceptance claims

Issue receipts are schema-locked to `issued`. Accepted claims exist only in a
`verified: true` response whose witness is schema-locked to `verified_once`.
Replay has its own `replay_rejected` witness.

The SQLite audit rows are an operational trail committed with each state
change. They are not append-only or tamper-evident against a database
administrator; export and protect them externally when that property matters.

### Commit and recovery durability

The reference ledger uses rollback-journal mode with `synchronous=EXTRA`, so a
successful SQLite commit includes the directory durability needed for journal
unlink on supported local filesystems. Database and keyring backups are emitted
under one keyring lifecycle lock, hash-manifested, and must be restored as a
pair. Every official backup is marked non-operational. Restore activation
revokes all authority from the snapshot before readiness can become true, so a
stale replay ledger cannot resurrect an unexpired bearer.

CLI credential output is fsynced before client creation or rotation mutates the
ledger. A failed command can therefore leave a non-authoritative credential
file, but cannot commit a replacement whose only raw secret was never made
durable.

## Residual risks

### Issuer compromise

An issuer credential permits arbitrary minting within its client's audience
allowlist. Rotate that role immediately or revoke the client. Onceproof cannot
distinguish a compromised trusted issuer from the original issuer.

### Verifier compromise

A verifier credential permits consuming and inspecting valid proofs for its
client. It cannot mint proofs. Rotate the verifier role and investigate audit
events.

### Bearer disclosure in transit

Possession is authority. The built-in server has no TLS. Network deployment
requires a TLS reverse proxy and redaction of `Authorization` headers and
request bodies from proxy, APM, and exception logs.

### Host compromise

An attacker with access to both keyring and SQLite can validate live bearer
material they already possess and impersonate role credentials they steal from
process memory or clients. Use OS access controls, encrypted storage, backups,
and a dedicated service account.

### Availability and abuse traffic

The ASGI server is fixed to one worker and rejects API work above 64 in-flight
requests with a contracted JSON 503. The ledger enforces per-client-role
quotas, but there is no distributed IP limiter.
Enforce connection and source-rate limits at the reverse proxy. A database
write outage fails verification closed.

### Multi-process and network filesystems

The supported v0.1 topology is one Onceproof HTTP process and a local SQLite
file. A host lock rejects a second server and rejects root-key mutation while
the server runs. Do not use NFS, SMB, or replicated SQLite; host file locks and
SQLite durability are not claimed there. A future transactional
server-database backend requires its own concurrency conformance run.

### Clock integrity

Expiry uses the host wall clock. Large backward clock jumps extend effective
lifetime. Run authenticated time synchronization and alert on clock steps.

## Explicitly out of scope

- CAPTCHA solving or proof of humanity.
- Device attestation, bot scoring, identity proofing, or authorization policy.
- Compatibility with hCaptcha, reCAPTCHA, OAuth access tokens, or any
  third-party verifier.
- Proof confidentiality after an issuer returns the bearer value.
- High availability or horizontal scaling in the SQLite release.
