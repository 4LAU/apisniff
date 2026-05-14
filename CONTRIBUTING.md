# Contributing

## Development setup

```bash
git clone https://github.com/4LAU/apisniff.git
cd apisniff
uv sync --dev
uv run pytest tests/ -v
uv run ruff check .
```

Requires Python 3.12+.

## Before opening a pull request

- Keep changes focused. Separate documentation, behavior, and refactors when possible.
- Add or update tests when behavior changes.
- Run `uv run pytest tests/ -v` and `uv run ruff check .`.
- If CLI flags or help text changed, regenerate command docs:

```bash
uv run python scripts/generate_command_docs.py
```

## Documentation

User-facing docs should be direct and specific. apisniff captures real traffic, so docs must call out privacy, authorization, and credential-handling behavior wherever it matters.

## Security-sensitive changes

Changes that affect capture storage, redaction, replay, proxy behavior, credential handling, or exported artifacts should explain the security impact in the pull request description.
