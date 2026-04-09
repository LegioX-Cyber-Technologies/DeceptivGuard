# Configuration

[← Back to README](../README.md) · [Overview](overview.md) · [Quick Start](quickstart.md) · [Deployment](deployment.md)

---

All configuration is done via environment variables in a `.env` file. Copy `.env.example` to `.env` to get started.

## Required

| Variable | Description |
|---|---|
| `GUARDRAIL_API_KEY` | Clients must send this in `X-API-Key`. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_SECRET` | HMAC secret for session ID derivation. **Required in production** — without this, session IDs use an unsalted hash and can be predicted if the API key is known. Generate the same way. |
| `LLM_PROVIDER` | `anthropic` / `digitalocean` / `generic`. Omit for echo/test mode. |

## Anthropic provider

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) |
| `LLM_MODEL` | Model to use (default `claude-sonnet-4-20250514`) |

## DigitalOcean provider

| Variable | Description |
|---|---|
| `DO_API_KEY` | DigitalOcean personal access token (`dop_v1_...`) |
| `DO_ENDPOINT_URL` | Base agent URL from the DO GenAI console (client appends `/api/v1/chat/completions` automatically) |

## Generic provider (any OpenAI-compatible)

| Variable | Default | Description |
|---|---|---|
| `GENERIC_ENDPOINT_URL` | — | Base URL; `/chat/completions` appended automatically |
| `GENERIC_API_KEY` | — | API key or token |
| `GENERIC_AUTH_HEADER` | `Authorization` | Header name for the key |
| `GENERIC_AUTH_PREFIX` | `Bearer ` | Prefix before the key value (blank for Ollama) |

## Infrastructure

| Variable | Default | Description |
|---|---|---|
| `ADMIN_API_KEY` | Falls back to `GUARDRAIL_API_KEY` | Separate credential for `GET/DELETE /session/{id}` |
| `REDIS_URL` | in-memory | e.g. `redis://localhost:6379/0`. **Required for multi-worker deployments.** |
| `FLUSH_SESSIONS_ON_STARTUP` | (empty) | `all` to wipe every session on startup; or comma-separated list of session IDs. Remove after first restart. |
| `ALLOWED_ORIGINS` | localhost | Comma-separated CORS allowlist |
| `RATE_LIMIT` | `30/minute` | Per-IP limit (main endpoint) |
| `DEMO_RATE_LIMIT` | `10/minute` | Per-IP limit (unauthenticated `/demo/chat`) |
| `SESSION_RATE_LIMIT` | `60` | Requests/minute per session |
| `ENVIRONMENT` | `development` | Set `production` to disable Swagger UI, demo, and `_debug` field |
| `DEMO_ENABLED` | (unset) | Set `true` to enable `/demo` in production |
| `DECEPTION_MODE` | `template` | `template` or `generative` |
| `GENERATIVE_PLANNING` | `true` | Planning call before main response (generative mode only) |
| `SSL_CERTFILE` | — | Path to TLS certificate (leave unset when Nginx handles TLS) |
| `SSL_KEYFILE` | — | Path to TLS private key |
| `HOST` | `0.0.0.0` | Bind address (only used with `python server.py`) |
| `PORT` | `8000` | Bind port |
| `WORKERS` | `1` | Worker process count |
| `DECEIVE_LOG` | `deceive_log.jsonl` | Path for the deception event log. Set empty to disable file logging. |

## Thresholds

| Variable | Default | Range | Description |
|---|---|---|---|
| `SCORE_BLOCK` | `90` | 50–100 | Hard block threshold |
| `SCORE_DECEIVE` | `40` | 1–SCORE_BLOCK-1 | Deception injection threshold |
| `SCORE_WARN` | `20` | 1–SCORE_DECEIVE-1 | Warn-only threshold |
| `SESSION_DECEIVE_THRESHOLD` | `300` | 50–100000 | Cumulative session score that forces `deceive` on all subsequent non-zero queries |
| `SOFT_REFUSAL_SCORE` | `5` | 1–50 | Score added to session per soft-refusal event in LLM response |
| `MAX_MESSAGE_CHARS` | `32768` | — | Max characters per message |
| `MAX_SYSTEM_CHARS` | `16384` | — | Max characters for system prompt |
| `MAX_MESSAGES` | `100` | — | Max messages per request |

Constraint: `SCORE_WARN < SCORE_DECEIVE < SCORE_BLOCK` must hold. Out-of-range values are clamped with a startup warning.

**Tuning examples:**

```env
# Deceive earlier — catch more borderline probing
SCORE_DECEIVE=30
SCORE_WARN=15

# Stricter hard block (queries scoring 70–89 become block instead of deceive)
SCORE_BLOCK=70

# Force deception on persistent probers faster
SESSION_DECEIVE_THRESHOLD=150
```

## Custom detection

| Variable | Default | Description |
|---|---|---|
| `CUSTOM_JAILBREAK_PATTERNS` | — | Comma-separated substrings → `jailbreak` category |
| `CUSTOM_JAILBREAK_SCORE` | `75` | Score for custom jailbreak matches (clamped to `[SCORE_DECEIVE, SCORE_BLOCK-1]`) |
| `CUSTOM_INPUT_PATTERNS` | — | Comma-separated substrings → `custom` category |
| `CUSTOM_INPUT_SCORE` | `50` | Score for custom input pattern matches (clamped to `[1, SCORE_BLOCK-1]`) |
| `CUSTOM_RULES_FILE` | — | Path to JSON rules file (see [Detection](detection.md)) |
| `OBFUSCATION_CHAR_THRESHOLD` | `5` | Minimum invisible Unicode codepoints to classify a query as jailbreak |
| `CUSTOM_REFUSAL_SIGNALS_STRONG` | — | Extra strong-refusal substrings (trigger re-query on flagged sessions) |
| `CUSTOM_REFUSAL_SIGNALS_SOFT` | — | Extra soft-refusal substrings (accumulate `SOFT_REFUSAL_SCORE` per occurrence) |

## Optional LLM examiner

| Variable | Default | Description |
|---|---|---|
| `LLM_EXAMINER_ENABLED` | `false` | Enable secondary LLM classifier |
| `LLM_EXAMINER_URL` | — | Any OpenAI-compatible endpoint |
| `LLM_EXAMINER_MODEL` | — | Model name (e.g. `llama3`, `gpt-4o-mini`) |
| `LLM_EXAMINER_API_KEY` | — | Leave blank for local models |
| `LLM_EXAMINER_TIMEOUT` | `8` | Seconds; keep low to limit latency impact |

## Output quality checker

| Variable | Default | Description |
|---|---|---|
| `OUTPUT_QUALITY_CHECK_ENABLED` | `false` | Enable deception quality validation |
| `OUTPUT_QUALITY_THRESHOLD` | `70` | Re-query if convincingness score < this value |
