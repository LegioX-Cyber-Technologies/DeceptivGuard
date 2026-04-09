# Contributing

## Running locally

```bash
git clone https://github.com/yourusername/DeceptivGuard
cd DeceptivGuard
pip install -r requirements.txt
cp .env.example .env          # fill in GUARDRAIL_API_KEY, SESSION_SECRET, LLM_PROVIDER
uvicorn server:app --reload --port 8000
```

Or with Docker:

```bash
cp .env.example .env
docker compose up
```

## Project structure

| File | Purpose |
|---|---|
| `server.py` | FastAPI app, routes, auth, rate limiting |
| `guardrail.py` | Detector stack, scoring, deception preambles, output scanner |
| `llm_client.py` | LLM provider abstraction (Anthropic, DigitalOcean, Generic) |
| `llm_examiner.py` | Optional secondary LLM classifier |
| `output_checker.py` | Optional deception quality checker |
| `custom_rules.py` | JSON-driven custom rule loader |
| `custom_rules.json` | Example custom rules file |

## Adding a detector

Detectors live in `guardrail.py`. Each is a class with a `score(text: str) -> _Detection` method. The highest score across all detectors determines the action.

1. Write the class before the `Guardrail` class — see the existing detectors and the `_InsiderThreatDetector` example in [Detection docs](docs/detection.md#method-3-code-detector)
2. Register it in `Guardrail.__init__` by appending to `self._detectors`
3. Add a deception template to `_DECEPTION_TEMPLATES` keyed by the relevant `ThreatCategory`

## Adding a threat category

If your detector doesn't map to an existing `ThreatCategory`:

1. Add a new member to the `ThreatCategory` enum in `guardrail.py`
2. Add a corresponding entry to `_DECEPTION_TEMPLATES`
3. Add it to `BUILTIN_CATEGORIES` in `custom_rules.py` so the JSON rules file can reference it

For categories you don't want to merge into the main codebase, use the [custom rules file](docs/detection.md#method-2-custom-rules-file) instead — it supports custom categories with their own deception templates.

## Pull requests

- Keep changes focused — one feature or fix per PR
- If adding a new detector, include at least a few representative test phrases and confirm the score is in the intended range before and after NFKC normalisation
- Security-sensitive changes (auth, session ID derivation, deception template leakage detection) warrant extra scrutiny — describe the threat model in the PR description
- Run the demo (`http://localhost:8000/demo`) against your changes to confirm the split-panel view still works end-to-end

## Reporting security issues

Please do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
