# Onceproof

Onceproof is a small, self-hosted issuer and one-time verifier for opaque
application proofs.

A trusted **issuer** can mint a short-lived proof. A separate **verifier** can
accept that proof exactly once, only for its bound client, subject, purpose,
and audience. The service persists the consume decision before returning
`verified: true`.

Onceproof does not solve CAPTCHAs, establish human presence, replace an
identity provider, or issue tokens for third-party systems. It transports a
decision made by your trusted issuer across a narrow, replay-resistant
boundary.

## Why opaque proofs

One-time verification needs a shared replay ledger even when a token is
signed. Onceproof therefore uses a 256-bit opaque bearer value and gives the
ledger one job: move it atomically from active to consumed.

- Raw proofs and API credentials are never stored in SQLite.
- Issuance and verification use different credentials.
- Proofs are bound to `client_id`, `subject`, `purpose`, and `audience`.
- Expiry and consume are checked under `BEGIN IMMEDIATE`.
- Exact verifier retries can use an idempotency key without reopening replay;
  the original decision is retained for at least 24 hours.
- Per-client issuer and verifier quotas are persisted in the same ledger and
  survive credential rotation.
- Receipts say `issued`; only a successful verifier response says
  `verified_once`.

## Quick start

Requires Python 3.11 or newer.

```console
git clone https://github.com/HOLYAC/onceproof.git
cd onceproof
python -m pip install .
onceproof init ./onceproof-instance
onceproof check --config ./onceproof-instance/onceproof.toml
```

Create a client. The credential file is made durable before its database rows
are activated, is created once, and is never overwritten. Raw credential
delivery to stdout is refused.
POSIX installs use owner-only mode; Windows operators must apply the service
account ACL described in the operations guide:

```console
onceproof client create \
  --config ./onceproof-instance/onceproof.toml \
  --name checkout \
  --audience https://api.example.test/checkout \
  --credentials-out ./checkout.credentials.json
```

Start the loopback-only reference server:

```console
onceproof serve --config ./onceproof-instance/onceproof.toml
```

Issue a proof with the `opi1` credential:

```console
curl --fail-with-body http://127.0.0.1:8787/v1/proofs \
  -H 'Authorization: Bearer <ISSUANCE_SECRET>' \
  -H 'Content-Type: application/json' \
  -d '{"subject":"user_123","purpose":"checkout","audience":"https://api.example.test/checkout"}'
```

Verify it with the distinct `opv1` credential:

```console
curl --fail-with-body http://127.0.0.1:8787/v1/verifications \
  -H 'Authorization: Bearer <VERIFICATION_SECRET>' \
  -H 'Idempotency-Key: checkout-42' \
  -H 'Content-Type: application/json' \
  -d '{"proof":"<PROOF>","subject":"user_123","purpose":"checkout","audience":"https://api.example.test/checkout"}'
```

The first matching verification returns `verified_once`. A second request
without the original idempotency key returns `replay_rejected`.

## Operations

Safe defaults are deliberate:

- `onceproof init` creates a separate keyring file and no demo client.
- Initialization creates the schema explicitly; later startup refuses a
  missing or empty database instead of silently creating a new ledger.
- The default bind is `127.0.0.1`.
- A non-loopback bind is rejected unless `allow_public_bind = true` is set.
- The single-worker Uvicorn server does not terminate TLS. Put it behind a TLS reverse
  proxy before any network exposure.
- An instance lock enforces one HTTP process per SQLite database and blocks
  root-key mutation while that process is running.
- Back up the database and keyring together. Neither is sufficient alone.

See [Operations](docs/OPERATIONS.md) for rotation, backup, cleanup, and
incident commands. See [Threat model](docs/THREAT_MODEL.md) before deploying.
Maintainers use the executable [release procedure](docs/RELEASE.md).

Inspect the live instance without exposing secrets:

```console
onceproof doctor --config ./onceproof-instance/onceproof.toml
onceproof key inspect --config ./onceproof-instance/onceproof.toml
onceproof db integrity-check --config ./onceproof-instance/onceproof.toml
```

## Contract

The OpenAPI 3.1 contract is shipped at
[`src/onceproof/openapi.json`](src/onceproof/openapi.json). Tests drive real
ASGI requests, validate bodies and security headers against it, compare the
published status matrix, and reject false boundary upgrades.

The two public commands are:

- `POST /v1/proofs`: authenticated with an issuer credential.
- `POST /v1/verifications`: authenticated with a verifier credential.

Health and readiness are intentionally separate:

- `GET /healthz`: the HTTP process is alive.
- `GET /readyz`: the database and current key are usable.

## Credential lifecycle

Rotate one role without exposing or changing the other:

```console
onceproof client rotate \
  --config ./onceproof-instance/onceproof.toml \
  --client-id <CLIENT_ID> \
  --role verification \
  --grace-seconds 300 \
  --credentials-out ./verification.rotation.json
```

Revoke an entire client, both credentials, and its outstanding proofs:

```console
onceproof client revoke \
  --config ./onceproof-instance/onceproof.toml \
  --client-id <CLIENT_ID> \
  --yes-revoke
```

Root hash-key rotation is two-phase. Add a new current key, rotate client
credentials, wait for old proofs and retention to expire, run cleanup, then
retire the unused key. Retirement fails while any database row still depends
on it.

Create a consistent database backup with SQLite's backup API:

```console
onceproof db backup \
  --config ./onceproof-instance/onceproof.toml \
  --output ./onceproof-backup
onceproof db verify-backup --input ./onceproof-backup
```

The command holds the keyring lifecycle lock while SQLite snapshots and emits
the database, matching keyring, and hash manifest into one private directory.
The manifest is published last; an interrupted directory is reconciled on
retry. A restored snapshot cannot serve until `db activate-restore`
irreversibly revokes every authority carried by that older point in time.

## Container

The image initializes `/var/lib/onceproof/instance` on its first server start,
binds `0.0.0.0:8787` only through the explicit public-bind initialization flag,
and exposes a readiness health check. Mount `/var/lib/onceproof` as a durable,
encrypted volume:

```console
docker build --file Containerfile --tag onceproof:release .
docker run --name onceproof -p 8787:8787 \
  -v onceproof-data:/var/lib/onceproof \
  onceproof:release
```

TLS and source-rate limiting still belong at the reverse proxy.

## Development

```console
python -m pip install -e ".[test]"
python -m unittest discover -s tests
coverage run -m unittest discover -s tests
coverage report
python -m build
python -m twine check dist/*
```

The core ledger uses the Python standard library. Uvicorn is the only runtime
dependency; `jsonschema`, coverage, and release tooling are test-only.

## Status

`0.1.0a1` is an alpha single-node reference implementation. Its security claims
are bounded to the executable invariants in the test suite and threat model.
Please report vulnerabilities through GitHub private vulnerability reporting,
not a public issue.

Apache-2.0 licensed.
