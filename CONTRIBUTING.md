# Contributing

Onceproof is small because its trust boundary must remain auditable.

1. Open an issue describing the invariant or operator problem before a broad
   change.
2. Add a failing test that crosses the real service or HTTP boundary.
3. Keep runtime dependencies minimal; each addition must remove more security
   risk than it introduces.
4. Preserve strict request fields, role separation, no raw bearer persistence,
   and atomic consume.
5. Update OpenAPI and the threat model with behavior changes.

Run before submitting:

```console
python -m pip install -e ".[test]"
coverage run -m unittest discover -s tests
coverage report
python -m build
```

Do not commit generated credentials, keyrings, databases, coverage output, or
real application identifiers.
