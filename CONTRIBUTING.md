# Contributing to roustabout

## Development setup

```bash
conda activate roustabout
pip install -e ".[dev,mcp]"
```

## Running tests

```bash
pytest --tb=short -q
```

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check .
ruff format --check .
```

Run both before submitting a PR. CI will catch failures but it saves a round-trip.

## Pull requests

1. Fork the repo and create a branch from `main`
2. Add tests for any new functionality
3. Ensure all tests pass and linting is clean
4. Open a PR with a clear description of the change

## Bug reports

Open an issue with:
- What you expected to happen
- What actually happened
- Your Docker version and Python version
- Minimal steps to reproduce
