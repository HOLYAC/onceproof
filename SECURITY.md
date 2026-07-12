# Security policy

## Supported versions

Only the newest `0.1.x` release receives security fixes while the project is in
alpha.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for `HOLYAC/onceproof`. Do not open
a public issue for a suspected vulnerability and do not include live proofs,
credential files, keyrings, production databases, or customer identifiers.

Include:

- affected version or commit;
- deployment topology;
- violated invariant;
- minimal reproduction using generated local credentials;
- impact and prerequisites;
- any proposed remediation.

You should receive an acknowledgement within seven days. No bounty or response
deadline is promised.

## Scope

Security reports about proof replay, cross-client acceptance, credential role
confusion, raw secret persistence, false witness upgrades, unsafe default bind,
or key retirement are in scope.

Requests to mint tokens accepted by unrelated third-party services, automate a
CAPTCHA, or bypass another provider's verifier are out of scope.
