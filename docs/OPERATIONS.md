# Operations

## Initialize

```console
onceproof init /srv/onceproof
onceproof check --config /srv/onceproof/onceproof.toml
```

Initialization refuses an existing directory. It creates:

- `onceproof.toml`: non-secret paths and network settings;
- `keyring.json`: root keyed-digest material;
- `onceproof.sqlite3`: schema-created during the explicit init command.

On POSIX, the instance directory is mode `0700` and secret files are `0600`.
Startup rejects symlinked state files, group/world-writable config or database
files, overexposed keyrings, and parents writable by another principal.
On Windows, apply an ACL that grants only the service identity and the recovery
operator access; POSIX mode bits are not an ACL substitute.

## Network exposure

The default listener is `127.0.0.1:8787`. Keep it there and forward from a TLS
reverse proxy. The proxy must:

- terminate TLS with certificate validation appropriate to clients;
- cap header size, body size, connection count, and request rate;
- never log `Authorization` values or request bodies;
- preserve response `Cache-Control: no-store`;
- send only the two POST API paths and health probes to Onceproof.

Setting `allow_public_bind = true` only permits a non-loopback socket. It does
not add TLS, authentication beyond role credentials, a firewall, or rate
limiting.

## Process model

Run exactly one Onceproof HTTP process for one SQLite file. The host instance
lock rejects a second owner; SQLite serializes consume transactions inside the
process. Do not configure a multi-worker process manager.

Use a local filesystem. Keep the database and rollback journal on the
same durable volume. Do not copy a live database file without SQLite's backup
mechanism or a clean process stop.

## Backup and restore

The database and keyring form one recovery unit. Create a consistent database
copy with:

```console
onceproof db backup \
  --config /srv/onceproof/onceproof.toml \
  --output /secure/onceproof-backup-20260712
onceproof db verify-backup --input /secure/onceproof-backup-20260712
```

The command creates one owner-only directory, writes an incomplete marker,
holds the keyring lifecycle lock, snapshots SQLite, writes the matching
keyring, and publishes a SHA-256 manifest last. A retry reconciles a directory
that contains only the marker and known partial members. Unknown files stop
reconciliation. Encrypt the backup set. Losing the keyring makes existing
credentials and retained proofs unverifiable. Losing the database removes
replay and audit state.

Every official database backup is recovery-sealed. It reports
`restore_required` and refuses issuance or verification because restoring an
older replay ledger could otherwise accept a bearer consumed after the backup.
There is no local observation that can distinguish that rollback from a
legitimate point-in-time restore.

Restore procedure:

1. Stop Onceproof and block upstream traffic.
2. Run `onceproof db verify-backup --input ...` before copying either member.
3. Restore `onceproof.sqlite3` and `keyring.json` from that directory together.
4. Restore owner-only permissions or the Windows service-account ACL.
5. Confirm `onceproof doctor --config ...` reports `restore_required: true`.
6. Irreversibly revoke every client, credential, and outstanding proof from
   the snapshot:

```console
onceproof db activate-restore \
  --config /srv/onceproof/onceproof.toml \
  --yes-invalidate-prior-authority
```

7. Create and distribute replacement clients, then run `onceproof check`.
8. Start on loopback and test issue, verify, and replay with a disposable
   client before reopening traffic.

Copying a live database file is not a supported backup and lacks the recovery
seal. Do not use it as a shortcut around activation.

## Client credential rotation

Rotate issuance and verification independently. A previous credential is
accepted only before `previous_valid_until`.

```console
onceproof client rotate \
  --config /srv/onceproof/onceproof.toml \
  --client-id <CLIENT_ID> \
  --role issuance \
  --grace-seconds 300 \
  --credentials-out /secure/issuer.rotation.json
```

Deploy the replacement, verify traffic, wait for grace to end, then remove the
credential file from staging. The file is made durable before activation.
When a command reports failure but the file exists, treat it as a recovery
artifact and inspect database state before retrying:

```console
onceproof client inspect \
  --config /srv/onceproof/onceproof.toml \
  --client-id <CLIENT_ID_FROM_FILE>
```

Match the non-secret credential ID from the file to the reported current or
previous row. Onceproof cannot retrieve a raw secret later.

## Root hash-key rotation

Stop the server before root-key mutation; the command fails with
`instance_busy` otherwise.

```console
onceproof key rotate --config /srv/onceproof/onceproof.toml
```

Start the single server so it loads the new keyring, then rotate both client
roles. Wait for outstanding proofs and retention to expire, run cleanup, and
retire the old key:

```console
onceproof cleanup --config /srv/onceproof/onceproof.toml
onceproof key retire --config /srv/onceproof/onceproof.toml --kid <OLD_KID>
```

Retirement fails with `key_still_in_use` while any credential or retained proof
depends on the key. That failure is the rotation safety gate.

## Incident response

For one leaked role, rotate that role with zero grace. For uncertain or broad
client compromise, revoke the client:

```console
onceproof client revoke \
  --config /srv/onceproof/onceproof.toml \
  --client-id <CLIENT_ID> \
  --yes-revoke
```

Revocation is final in v0.1. It disables both credentials and expires every
outstanding unconsumed proof for the client.

If the keyring may be exposed, isolate the host, preserve database and process
evidence, provision a new instance, create new clients, and move callers. Do
not treat root-key rotation on the compromised host as containment.
