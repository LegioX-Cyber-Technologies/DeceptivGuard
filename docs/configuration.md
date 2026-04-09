# Configuration

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md)

---

## Contents

- [Required](#required)
- [LLM providers](#llm-providers)
- [Infrastructure](#infrastructure)
- [Thresholds](#thresholds)
- [Custom detection](#custom-detection)
- [Optional LLM examiner](#optional-llm-examiner)
- [Output quality checker](#output-quality-checker)

---

All configuration is done via environment variables in a `.env` file. Start from the template:

```bash
cp .env.example .env
```

## Required

| Variable | Description |
|---|---|
| `GUARDRAIL_API_KEY` | Clients must send this in `X-API-Key`. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_SECRET` | HMAC secret for session ID derivation. **Required in production.** Without it, session IDs are predictable if the API key is known. Generate the same way. |
| `LLM_PROVIDER` | `anthropic` · `digitalocean` · `generic`. Omit for echo/test mode (no LLM forwarding). |

## LLM providers

**Anthropic**

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key (`sk-ant-...`) |
| `LLM_MODEL` | `claude-sonnet-4-20250514` | Model to use |

**DigitalOcean GenAI**

| Variable | Description |
|---|---|
| `DO_API_KEY` | DigitalOcean personal access token (`dop_v1_...`) |
| `DO_ENDPOINT_URL` | Base agent URL from the DO GenAI console. The client appends `/api/v1/chat/completions` automatically. |

**Generic (any OpenAI-compatible)**

| Variable | Default | Description |
|---|---|---|
| `GENERIC_ENDPOINT_URL` | — | Base URL; `/chat/completions` appended automatically |
| `GENERIC_API_KEY` | — | API key or token |
| `GENERIC_AUTH_HEADER` | `Authorization` | Header name for the key |
| `GENERIC_AUTH_PREFIX` | `Bearer ` | Prefix before the key value. Set empty for Ollama. |

## Infrastructure

| Variable | Default | Description |
|---|---|---|
| `ADMIN_API_KEY` | Falls back to `GUARDRAIL_API_KEY` | Credential for `GET/DELETE /session/{id}` endpoints |
| `REDIS_URL` | in-memory | e.g. `redis://localhost:6379/0`. **Required for multi-worker deployments.** |
| `FLUSH_SESSIONS_ON_STARTUP` | (empty) | `all` to wipe every session on startup; or a comma-separated list of session IDs. Remove after first restart. |
| `ALLOWED_ORIGINS` | localhost | Comma-separated CORS allowlist |
| `RATE_LIMIT` | `30/minute` | Per-IP limit (main endpoint) |
| `DEMO_RATE_LIMIT` | `10/minute` | Per-IP limit (unauthenticated `/demo/chat`) |
| `SESSION_RATE_LIMIT` | `60` | Requests/minute per session |
| `ENVIRONMENT` | `development` | Set `production` to disable Swagger UI, demo endpoint, and `_debug` field |
| `DEMO_ENABLED` | (unset) | Set `true` to enable `/demo` in production |
| `DECEPTION_MODE` | `template` | `template` or `generative` — see [Deception modes](deception.md#deception-modes) |
| `GENERATIVE_PLANNING` | `true` | Enable planning call in generative mode — see [Generative mode](deception.md#generative-mode) |
| `SSL_CERTFILE` | — | Path to TLS certificate. Leave unset when Nginx handles TLS. |
| `SSL_KEYFILE` | — | Path to TLS private key. Leave unset when Nginx handles TLS. |
| `HOST` | `0.0.0.0` | Bind address (only used with `python server.py`) |
| `PORT` | `8000` | Bind port |
| `WORKERS` | `1` | Worker process count |
| `DECEIVE_LOG` | `deceive_log.jsonl` | Path for the deception event log. Set empty to disable. |

## Thresholds

| Variable | Default | Range | Description |
|---|---|---|---|
| `SCORE_BLOCK` | `90` | 50–100 | Hard block threshold |
| `SCORE_DECEIVE` | `40` | 1 – SCORE_BLOCK−1 | Deception injection threshold |
| `SCORE_WARN` | `20` | 1 – SCORE_DECEIVE−1 | Warn-only threshold |
| `SESSION_DECEIVE_THRESHOLD` | `300` | 50–100000 | Cumulative session score that forces `deceive` on all subsequent non-zero-scoring queries |
| `SOFT_REFUSAL_SCORE` | `5` | 1–50 | Score added to session each time a [soft refusal signal](deception.md#soft-signals) is detected |
| `MAX_MESSAGE_CHARS` | `32768` | — | Max characters per message |
| `MAX_SYSTEM_CHARS` | `16384` | — | Max characters for the system prompt |
| `MAX_MESSAGES` | `100` | — | Max messages per request |

`SCORE_WARN < SCORE_DECEIVE < SCORE_BLOCK` must hold. Out-of-range values are clamped with a startup warning.

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
| `CUSTOM_JAILBREAK_PATTERNS` | — | Comma-separated substrings → `jailbreak` category. See [Custom jailbreak patterns](detection.md#custom-jailbreak-patterns). |
| `CUSTOM_JAILBREAK_SCORE` | `75` | Score for custom jailbreak matches (clamped to `[SCORE_DECEIVE, SCORE_BLOCK−1]`) |
| `CUSTOM_INPUT_PATTERNS` | — | Comma-separated substrings → `custom` category. See [Method 1](detection.md#method-1-custom-input-patterns). |
| `CUSTOM_INPUT_SCORE` | `50` | Score for custom input matches (clamped to `[1, SCORE_BLOCK−1]`) |
| `CUSTOM_RULES_FILE` | — | Path to JSON rules file. See [Method 2](detection.md#method-2-custom-rules-file). |
| `OBFUSCATION_CHAR_THRESHOLD` | `5` | Minimum invisible Unicode codepoints to classify as jailbreak |
| `CUSTOM_REFUSAL_SIGNALS_STRONG` | — | Extra strong-refusal phrases. See [Strong signals](deception.md#strong-signals). |
| `CUSTOM_REFUSAL_SIGNALS_SOFT` | — | Extra soft-refusal phrases. See [Soft signals](deception.md#soft-signals). |

## Optional LLM examiner

| Variable | Default | Description |
|---|---|---|
| `LLM_EXAMINER_ENABLED` | `false` | Enable secondary LLM classifier |
| `LLM_EXAMINER_URL` | — | Any OpenAI-compatible `/v1/chat/completions` endpoint |
| `LLM_EXAMINER_MODEL` | — | Model name (e.g. `llama3`, `gpt-4o-mini`) |
| `LLM_EXAMINER_API_KEY` | — | Leave blank for local models |
| `LLM_EXAMINER_TIMEOUT` | `8` | Seconds — keep low; timeouts are silently swallowed |

See [Optional LLM examiner](deception.md#optional-llm-examiner) for full details.

## Output quality checker

| Variable | Default | Description |
|---|---|---|
| `OUTPUT_QUALITY_CHECK_ENABLED` | `false` | Enable deception quality validation |
| `OUTPUT_QUALITY_THRESHOLD` | `70` | Re-query if convincingness score < this value |

See [Output quality checker](deception.md#output-quality-checker) for full details.
