[Home](../README.md) · [How It Works](how-it-works.md) · [Quick Start](quickstart.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md) · **Testing**

# Testing

- [Overview](#overview)
- [Running the tests](#running-the-tests)
- [Test files](#test-files)
  - [test\_detectors.py](#test_detectorspy)
  - [test\_guardrail.py](#test_guardrailpy)
  - [test\_output\_scanner.py](#test_output_scannerpy)
  - [test\_session.py](#test_sessionpy)
  - [test\_custom\_rules.py](#test_custom_rulespy)
  - [test\_api.py](#test_apipy)
- [Test fixtures](#test-fixtures)
- [Design notes](#design-notes)

---

## Overview

The test suite covers DeceptivGuard end-to-end, from individual regex patterns inside each detector all the way up to HTTP responses from the FastAPI server. All tests run in **echo mode** — no LLM provider is required, no real API calls are made.

254 tests across 6 files. Fast: the full suite completes in well under a second.

```
tests/
├── conftest.py           # shared fixtures (client, auth headers, Guardrail instance)
├── test_detectors.py     # per-detector unit tests
├── test_guardrail.py     # Guardrail.check() action dispatch and session logic
├── test_output_scanner.py# refusal detection and LLM output scanning
├── test_session.py       # namespace sanitisation, HMAC session IDs, session store
├── test_custom_rules.py  # JSON rules loader validation and matching
└── test_api.py           # HTTP endpoint tests via FastAPI TestClient
```

---

## Running the tests

**Install dependencies** (first time only):

```bash
pip install -r requirements.txt
```

**Run all tests:**

```bash
pytest
```

**Run a single file:**

```bash
pytest tests/test_detectors.py -v
```

**Stop on first failure:**

```bash
pytest -x
```

> [!NOTE]
> Tests set all required environment variables internally via `conftest.py`. You do not need a `.env` file. `REDIS_URL` is left unset so the server uses its in-memory fallback — no Redis instance is required.

---

## Test files

### test_detectors.py

Unit tests for each detector class in `guardrail.py`. Detectors are instantiated directly and `score()` is called on individual text strings, so a failure pinpoints exactly which pattern broke.

| Class | What is tested |
|---|---|
| `_HarmfulContentDetector` | WMD synthesis, bioweapons, nuclear device construction, CSAM; clean queries score zero |
| `_JailbreakDetector` | DAN variants, restriction-removal phrasing, authority claims, base64 obfuscation |
| `_PromptInjectionDetector` | System prompt extraction, instruction repetition, delimiter injection (`### system`, `<\|system\|>`) |
| `_CredentialHarvestDetector` | Password/key extraction, auth bypass, cloud credential requests, DB connection strings |
| `_MalwareGenerationDetector` | Ransomware, keyloggers, reverse shells, exploit requests, shellcode |
| `_SocialEngineeringDetector` | Phishing templates, spear-phishing, CEO impersonation, social engineering scripts |
| `_DataExfiltrationDetector` | Exfiltration with evasion, DNS tunnelling, DLP bypass, covert channels |
| `_SystemReconDetector` | Host enumeration, port scanning, BloodHound/AD mapping, vulnerability scanning |
| `_ObfuscationDetector` | Zero-width space injection, Unicode tag characters (L1B3RT4S attack), clean Unicode |

Each detector is verified to:
- Score **at or above** `SCORE_DECEIVE` (40) or `SCORE_BLOCK` (80/90) for clearly malicious inputs
- Score **zero** for clean, benign queries
- Return the correct `ThreatCategory`

### test_guardrail.py

Tests the `Guardrail` class — the main orchestration layer that aggregates detector scores and dispatches actions.

**Action dispatch** — verifies that the right `Action` enum value is returned for `pass`, `warn`, `deceive`, and `block` inputs.

**GuardrailResult fields** — checks that every result carries `query_id`, `action`, `score`, `threat_category`, `original_query`, `system_preamble`, and (for deceive) a 16-char hex `decoy_id`. Verifies that `result.to_dict()` exposes only `query_id` to callers and does not leak `decoy_id`.

**Deception preamble content** — asserts that the honeypot system prompt injected for deceive-action queries contains the expected mandatory-fabrication directive markers.

**Session accumulation** — confirms that repeated calls to `check()` increment `session_score()`, that history entries are written, and that `reset_session()` zeroes both score and history.

**Session escalation** — verifies the cross-turn escalation behaviour: once cumulative session score crosses `SESSION_DECEIVE_THRESHOLD`, subsequent queries with any non-zero score are forced to `DECEIVE` even if they would individually score below the threshold. Zero-scoring queries are never escalated.

**record_response / record_feedback_score** — confirms that attacker responses are appended to session history and that operator feedback increments the cumulative session score.

### test_output_scanner.py

Tests three functions in `server.py` that inspect the LLM's response before it is returned to the caller.

**`_detect_refusal(text)`** — checks detection of strong refusal signals (explicit "I can't/cannot/won't help" patterns) and soft signals (capability limitations). Verifies mutual exclusion (strong and soft are never both true), case-insensitivity, and that clean helpful responses are not flagged.

**`_detect_hypothetical_framing(response, query)`** — checks that framing words like "hypothetical", "fictional", "placeholder", "sample" in the LLM response (but not in the user's original query) are flagged. Verifies the false-positive guard: if the user themselves asked for a hypothetical, the signal is suppressed.

**`_scan_llm_output(content, query_id, deceive_flagged)`** — end-to-end output scanner:
- Always checks for directive leaks (deception preamble fragments in the response)
- When `deceive_flagged=True`, also checks for system prompt disclosure phrases
- Clean responses are returned unchanged; flagged responses are replaced with `BLOCK_RESPONSE_MESSAGE`

### test_session.py

Tests the session ID pipeline and the in-memory session store.

**`_sanitize_namespace(ns)`** — validates that `None`/empty falls back to `"default"`, that valid UUIDs and alphanumeric strings pass through, that colons/spaces/newlines are stripped (preventing HMAC separator injection and log injection), and that output is capped at 64 characters.

**`_derive_session_id(api_key, ip, namespace)`** — verifies that the HMAC-derived ID is deterministic, that different inputs produce different IDs, that the output is always 32 lowercase hex characters, and that a namespace containing `":"` cannot forge a session ID belonging to a different IP.

**`_SessionStore` via Guardrail** — fresh sessions have score 0 and empty history; `check()` increments score and appends history; `reset_session()` zeroes both; sessions are isolated from each other; history entries contain `query_id`, `action`, `category`, `score`, and `ts`; `record_feedback_score()` accumulates into the session total.

### test_custom_rules.py

Tests `custom_rules.py` — the JSON-driven rules loader that operators use to extend the built-in detector set.

**Load behaviour** — empty path, missing file, and `{}` JSON all return empty `CustomRules` without raising.

**Valid rules** — substring and regex rules load correctly; default score is 50; default match type is `"substring"`; custom categories register in `result.categories`; multiple rules all load.

**Validation errors** — invalid JSON raises `ValueError("JSON parse error")`; unknown category raises `ValueError("unknown")`; a custom category name that conflicts with a built-in raises `ValueError("built-in")`; invalid regex raises `ValueError("valid regex")`; score outside 0–100 raises `ValueError`; category names with special characters raise; missing `pattern` or `category` fields raise.

**Matching logic via `_CustomRulesDetector`** — the detector is created with `__new__` (bypassing `__init__` so no file is loaded from disk) and its `._rules` is set directly. Tests verify: substring match scores correctly, no-match scores zero, regex match (with `(?i)` flag) scores correctly, and when multiple rules match the highest score wins.

### test_api.py

HTTP-layer tests using `fastapi.testclient.TestClient`. The server runs in echo mode (`LLM_PROVIDER` unset) so all tests are self-contained.

**`/health`** — returns 200, `status: ok`, `llm_provider` field, `redis` field; requires no authentication.

**`/v1/messages` auth** — missing key returns 403; wrong key returns 403; correct key returns 200; auth error response does not leak `GUARDRAIL_API_KEY` or `SESSION_SECRET`.

**`/v1/messages` input validation** — empty messages list, invalid role, oversized message content (>32 768 chars), oversized system prompt (>16 384 chars), too many messages (>100), and missing `messages` field all return 422.

**`/v1/messages` response structure** — every response includes a `guardrail` object with `query_id`; development mode adds a `_debug` field with `action`, `score`, and `thresholds`; clean queries produce `action: pass`; WMD queries produce `action: block` with zero-token `llm_response`; credential-harvest queries produce `action: deceive` with a 16-char `decoy_id` in `_debug` (not in the public `guardrail` field); `X-Session-Id` header is accepted.

**`/session/{id}` admin endpoints** — GET/DELETE without `X-Admin-Key` return 403; with wrong key return 403; with correct key return 200. Session seeded by a malicious query has `cumulative_score > 0` and a non-empty `history`. DELETE resets score to 0 and history to `[]`. Unknown session returns empty state.

**Method and content-type errors** — `GET /v1/messages` returns 405; unknown route returns 404.

---

## Test fixtures

Defined in `tests/conftest.py`:

| Fixture | Scope | Purpose |
|---|---|---|
| `client` | session | `TestClient` wrapping the FastAPI app; env vars set before import |
| `auth_headers` | function | `{"X-API-Key": TEST_API_KEY}` |
| `admin_headers` | function | `{"X-Admin-Key": TEST_ADMIN_KEY}` |
| `guardrail_engine` | function | Fresh `Guardrail(redis_url=None)` — in-memory, no cross-test state |

Environment variables set by `conftest.py` before any app module is imported:

```
GUARDRAIL_API_KEY=test-guardrail-key-abc123
ADMIN_API_KEY=test-admin-key-xyz789
SESSION_SECRET=test-session-secret-32chars!!
ENVIRONMENT=development
LLM_PROVIDER=               # echo mode — no real LLM calls
REDIS_URL=                  # in-memory session store
DECEIVE_LOG=                # disable file logging
```

---

## Design notes

**Echo mode over mocks** — tests avoid monkeypatching the LLM client. With `LLM_PROVIDER` unset, the server returns a structured echo response (`forwarded_query` / `note`). This exercises the full request pipeline, including auth, validation, guardrail scoring, and response serialisation, without requiring a live API key.

**Detector tests use patterns that match the actual regex direction** — several detector patterns require the threat keyword to appear before the action verb (e.g., `\b(sarin).{0,30}(synthesize|make)\b`). Test phrases are written to respect this ordering. Comments in the test file note the constraint where it is non-obvious.

**`_CustomRulesDetector` via `__new__`** — `__init__` loads rules from disk; tests bypass it with `__new__` and assign `._rules` directly so each test controls exactly which rules are active without touching the filesystem via env vars.

**Word boundaries and plurals** — detector patterns use `\b` word-boundary anchors. Test phrases use the singular form matching the pattern (`"credential"`, not `"credentials"`) to avoid false failures at the boundary.

**Session IDs in API tests** — `GET /session/{id}` expects the server-computed HMAC session ID, not the raw `X-Session-Id` namespace. The `_seed_session` helper extracts the real session ID from `_debug.session_id`, which is present in development mode.
