# Contributing to Scry

Thanks for your interest! Scry is a defensive cyber-threat-intelligence
platform. Contributions are welcome under the terms of the
[Apache 2.0 license](./LICENSE).

## Ground rules

1. **Defensive use only.** All contributions must respect the safety
   boundaries in [SECURITY.md](./SECURITY.md): fail-closed collection
   policies, no credential/PII collection, no malware download or execution,
   no offensive automation, dark-web collection disabled by default.
2. **No secrets, ever.** Never commit API keys, tokens, or personal data.
   `.env`, `.cti_secret`, databases, and logs are gitignored — keep it that
   way. Use placeholders in docs and examples. A pre-commit hook
   (`.githooks/pre-commit`, enabled via `core.hooksPath`) blocks
   credential-shaped strings in staged diffs, and CI runs gitleaks on every
   push and pull request. If a match is an intentional test fixture, commit
   with `SKIP_SECRET_SCAN=1`.
3. **Safe-by-default.** New capabilities that carry risk must ship disabled
   behind an explicit `CTI_ENABLE_*` setting.

## How to contribute

1. Fork the repo and create a branch from `main`.
2. Set up your environment and read
   [docs/development.md](./docs/development.md) — it covers layout, testing,
   code style, and how to add sources/collectors/enrichers.
3. Make your change with tests. All existing tests must pass:

   ```bash
   pytest -q
   ruff check .
   black --check .
   ```

4. Update documentation when behavior changes (the `docs/` guides and the
   relevant root docs).
5. Open a pull request with a clear description of the change and its
   security posture impact, if any.

## Release procedure

Releases follow the end-of-track checklist (see
[HANDOFF.md](./HANDOFF.md) §2.2 for the full convention):

1. Bump the version in `scry/main.py` and `pyproject.toml`.
2. Add a `[X.Y.Z]` section to `CHANGELOG.md` (Keep a Changelog format).
3. Update `README.md` ("What's new in X.Y.Z" + feature bullets).
4. **Update `HANDOFF.md`'s current-state section** — version number, test
   count, release date, and build-journal row — so the handoff document
   stays accurate for anyone (human or AI) picking up the project.
5. Commit as `Release vX.Y.Z: <headline>`, tag `vX.Y.Z`, push branch + tag.
6. Publish the GitHub release with the changelog section as notes; verify
   tag == `HEAD` == remote `HEAD` and the working tree is clean.

## Reporting issues

- **Bugs / feature requests:** open a GitHub issue with reproduction steps.
- **Security vulnerabilities:** do NOT open a public issue — see the
  reporting guidance in [SECURITY.md](./SECURITY.md).

## Code of conduct

Be respectful and constructive. This project exists to help defenders.
