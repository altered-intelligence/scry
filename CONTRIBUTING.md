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

## Reporting issues

- **Bugs / feature requests:** open a GitHub issue with reproduction steps.
- **Security vulnerabilities:** do NOT open a public issue — see the
  reporting guidance in [SECURITY.md](./SECURITY.md).

## Code of conduct

Be respectful and constructive. This project exists to help defenders.
