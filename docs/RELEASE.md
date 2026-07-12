# Release procedure

Onceproof releases are built once and promoted from the resulting `dist/`
artifacts. Do not rebuild between checks and publication.

## Local gate

```console
python -m pip install -e ".[test]"
ruff check src tests scripts
coverage erase
coverage run -m unittest discover -s tests
coverage report
python -m compileall -q src
python -m build
python -m twine check dist/*
```

Install the wheel and sdist into separate empty environments. Run
`scripts/release_smoke.py` with each environment's Python. The script starts a
real Uvicorn process and proves issue, verify, exact idempotent retry, replay,
doctor, and bearer-log absence.

The container build is a separate gate because the local Windows workstation
may not have Docker:

```console
docker build --file Containerfile --tag onceproof:release .
docker run --rm onceproof:release --version
docker run --detach --name onceproof-release onceproof:release
docker inspect --format '{{.State.Health.Status}}' onceproof-release
docker rm --force onceproof-release
```

CI repeats the suite and wheel smoke on Windows and exercises the runtime
container bootstrap until `/readyz` is healthy.

## Publication

1. Confirm the version matches `pyproject.toml`, `onceproof.__version__`,
   OpenAPI, and the changelog.
2. Commit the exact reviewed tree and push `main`.
3. Wait for CI, CodeQL, and the container job.
4. Create a signed or annotated `v<version>` tag at that commit.
5. Create a prerelease and attach the already checked wheel and sdist.
6. Publish to PyPI only after Trusted Publishing is configured with manual
   environment approval. PyPI publication is not implied by a GitHub release.
7. Record SHA-256 checksums in the release notes.

`0.1.0a1` remains explicitly alpha: one process, one local rollback-journal
SQLite database, one Uvicorn worker, and no claim of identity, humanity,
horizontal scaling, or third-party token compatibility.
