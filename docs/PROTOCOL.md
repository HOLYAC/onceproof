# Onceproof protocol v1

## Frame

Onceproof carries a trusted application's decision to another application
boundary. It does not decide whether a person, device, payment, or workflow is
trustworthy. That evidence belongs to the issuer.

The protocol separates four roles:

1. **Administrator** creates clients and rotates or revokes credentials through
   the local CLI.
2. **Issuer** possesses an `opi1` credential and can mint proofs for one client.
3. **Holder** transports an opaque `op1` proof.
4. **Verifier** possesses an `opv1` credential and can atomically consume proofs
   for the same client.

Issuer and verifier credentials are intentionally not interchangeable.

## Proof lifecycle

```text
absent -> issued -> verified_once
                 -> rejected (no state change)
                 -> expired
verified_once -> replay_rejected
```

A consumed row is classified as `replay_rejected` even after its proof TTL.
Expired proof rows are retained for one additional hour by default; after that
cleanup horizon, the forgotten bearer is safely classified as `invalid`.

An issue receipt contains `state: issued`. It is evidence that the issuer
endpoint returned a bearer proof, nothing more. The only acceptance witness is
a successful verifier response with `verified: true` and
`witness.state: verified_once`.

## Bindings

Every proof is bound to:

- `client_id`: tenant selected by the issuer credential;
- `subject`: an application-defined opaque identifier;
- `purpose`: a stable operation name;
- `audience`: an exact URI or URN allowed by the client policy;
- `issued_at` and `expires_at`.

The verifier must supply `subject`, `purpose`, and `audience`.
A mismatch rejects without consuming, so a corrected request can still verify
before expiry.

## Bearer representation

Proofs contain 32 random bytes from Python's operating-system-backed
`secrets` source. The token includes a non-secret hash-key identifier so the
service can authenticate old proofs during key rotation:

```text
op1.<hash_kid>.<base64url_random>
```

SQLite stores only `HMAC-SHA-256(hash_key, proof)`. The same keyed-digest rule
applies to role credentials. A database copy without the keyring cannot derive
live bearer values; a keyring copy without the database has no proof ledger.
For every referenced KID, SQLite also stores a domain-separated key check.
Readiness compares it with the loaded key material, so a same-name but
different recovery keyring fails closed.

This design follows the opaque-token and authenticated-introspection shape in
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), while adding one-time
consume semantics. It is not an OAuth implementation.

## Atomic verification

Verification opens `BEGIN IMMEDIATE` in SQLite rollback-journal mode with
`synchronous=EXTRA`, samples the decision time after acquiring the lock, then
performs these checks under that lock:

1. verifier credential and client are active;
2. an exact idempotent result does not already exist;
3. proof digest belongs to the same client;
4. a consumed proof is rejected as replay; otherwise expiry is checked;
5. all supplied bindings match;
6. conditional update changes `consumed_at` from `NULL` exactly once;
7. verifier result and audit event are persisted;
8. transaction commits before `verified: true` is returned.

Concurrent requests therefore have one winner. Signed self-contained tokens
alone would not provide this property because replay is mutable state.

## Idempotency

The `Idempotency-Key` HTTP header is scoped to the authenticated verifier
client. The service stores a fingerprint of the canonical parsed proof,
subject, purpose, and audience plus its result; JSON byte formatting is not
part of that identity.

- Repeating the same key and request returns the original result, including the
  original verification witness.
- Reusing the key for a different request returns HTTP 409.
- Omitting the key means a second redemption is an ordinary replay rejection.
- The original decision is retained for at least 24 hours. After that cleanup
  horizon the key may produce a new decision or bind to a new request.

Issue requests intentionally have no idempotency key in v1 because returning an
identical bearer proof would require persisting recoverable bearer material.

## Quotas and cleanup

Each client has separate issuer and verifier limits per rolling 60-second
window. Rate slots are stored transactionally in SQLite. An exact idempotent
verification retry returns its committed result before spending another slot.
New requests beyond quota return HTTP 429 with `Retry-After` and inspect or
mutate no proof.

Active request traffic triggers bounded cleanup at most once every five
minutes. Operators can also run `onceproof cleanup`; `doctor` reports the last
completed cleanup timestamp. Default retention is one hour beyond proof expiry
for proof rows, 24 hours for verification/idempotency rows, and seven days for
audit rows.

## Error privacy

Credential authentication precedes body parsing. Unauthenticated requests
return HTTP 401 with `WWW-Authenticate: Bearer realm="onceproof"` and no proof
or body-validation metadata. An
authenticated verifier receives claims only on `verified: true`. A proof from
another client is indistinguishable from an unknown proof.

## References

- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) describes bearer-token
  disclosure and replay threats.
- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) defines authenticated
  opaque-token introspection.
- [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577) requires secure randomness
  and discusses origin binding and anti-replay for redeemable tokens.
- [Python `secrets`](https://docs.python.org/3/library/secrets.html) documents
  the OS-backed generator and the 32-byte token recommendation.
