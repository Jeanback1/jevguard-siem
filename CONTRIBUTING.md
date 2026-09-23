# Contributing

JevGuard welcomes defensive-security contributions that make Linux telemetry,
triage, evaluation, or documentation more reliable.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Do not commit API keys, real incident data, personal addresses, or credentials.
Fixtures must use reserved documentation IP ranges and invented identities.

## Adding an AI provider

Implement the `DecisionProvider` protocol in `jevguard.decision`. A provider
must return only the shared classifications, severities, and actions; validate
all remote output; use a timeout; and fail closed to local review. Add its
configuration through environment variables and include unit tests with no
live network dependency.

New providers must not execute response actions. Decisions and containment are
separate components by design.
