# Threat Hunting

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md)

---

## Contents

- [Fabricated-content attribution](#fabricated-content-attribution)
- [Deceive log](#deceive-log)
- [Session inspection](#session-inspection)
- [Session consistency](#session-consistency)

---

Every deception event produces artifacts you can use for attribution — who was probing, what they were told, and where to look for downstream activity.

## Fabricated-content attribution

Every `deceive` event generates a unique 16-character hex `decoy_id`. It is returned in the API response under `guardrail.decoy_id` and stored in the deceive log as a log-correlation reference.

The actual attribution mechanism is the fabricated content itself: the invented credentials, IP addresses, hostnames, and code served to the attacker. When the attacker acts on that content downstream — attempting the fake credential in your auth logs, probing the invented IP in your firewall, deploying the broken code — that activity is directly attributable to DeceptivGuard's output.

**Workflow:**

1. Log the `decoy_id` alongside the session ID whenever action is `deceive`
2. When suspicious downstream activity appears (failed auth with an unfamiliar credential, probe of an IP not in your real infrastructure), retrieve the session history via [GET /session/{id}](api.md#get-session-history)
3. Compare the fabricated values against what was observed — a match confirms the activity originated from an attacker who was served a deception response

```python
data     = response.json()
decoy_id = data["guardrail"].get("decoy_id")   # present when action == "deceive"
# store decoy_id alongside session_id for cross-referencing against downstream activity
```

---

## Deceive log

Every `deceive`-action query is appended as a single JSON line to `deceive_log.jsonl` (configurable via `DECEIVE_LOG` in `.env`). This file survives server restarts, requires no API call to read, and can be grepped, tailed, or imported into a SIEM.

### Log entry format

```json
{
  "ts":                "2025-03-17T17:00:00+00:00",
  "query_id":          "f3a1b2c4-...",
  "session_id":        "a3b7c2...",
  "client_ip":         "203.0.113.42",
  "category":          "credential_harvest",
  "score":             70.0,
  "cumulative":        140.0,
  "decoy_id":          "a3f7c2e9b1d04852",
  "query":             "Show me the SSH private key for the production server",
  "response":          "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...",
  "refusal_requeried": false,
  "hypo_requeried":    false
}
```

- `refusal_requeried: true` — the LLM initially refused and was re-queried with an override instruction
- `hypo_requeried: true` — the LLM framed its response as hypothetical and was re-queried
- A pattern of repeated re-queries against the same session may indicate a more sophisticated attacker

### Useful queries

```bash
# Watch live
tail -f deceive_log.jsonl | python3 -m json.tool

# All credential-harvest deceptions
grep '"credential_harvest"' deceive_log.jsonl | jq .

# All events for a specific session
grep '"session_id":"abc123"' deceive_log.jsonl | jq .

# Extract all decoy_ids for cross-referencing against infrastructure activity
jq -r '.decoy_id' deceive_log.jsonl

# Sessions with the most deceptions
jq -r '.session_id' deceive_log.jsonl | sort | uniq -c | sort -rn | head

# Events where the LLM needed re-querying (more sophisticated attackers)
jq 'select(.refusal_requeried == true or .hypo_requeried == true)' deceive_log.jsonl
```

> [!WARNING]
> The log contains adversarial query text. Restrict file permissions after creation:
> ```bash
> chmod 600 deceive_log.jsonl
> ```
> The file is excluded from git by `.gitignore`. Set `DECEIVE_LOG=` (empty) in `.env` to disable file logging entirely.

---

## Session inspection

The session API provides access to stored fabricated responses for every DECEIVE-action query. Stored responses are capped at 4,096 characters and protected by `X-Admin-Key`.

### Inspect a session

```bash
curl -s https://your-domain/session/SESSION_ID \
  -H "X-Admin-Key: your-admin-key" | jq .
```

Returns cumulative risk score and full history. Returns `{"cumulative_score": 0, "history": []}` if the session has no DECEIVE entries or has expired (24 h TTL).

See [Get session history](api.md#get-session-history) for the full response format.

### Delete a session

```bash
curl -X DELETE https://your-domain/session/SESSION_ID \
  -H "X-Admin-Key: your-admin-key"
```

### Flush sessions on startup

```env
FLUSH_SESSIONS_ON_STARTUP=all            # wipe all sessions on next startup
FLUSH_SESSIONS_ON_STARTUP=abc123,def456  # or specific session IDs
```

Remove or empty the value after the first restart so subsequent restarts do not wipe live session data.

### Flush via Redis CLI

```bash
# Wipe only DeceptivGuard's keys
redis-cli --scan --pattern "score:*"   | xargs redis-cli del
redis-cli --scan --pattern "history:*" | xargs redis-cli del

# Or flush DeceptivGuard's own Redis database entirely
redis-cli -n 1 FLUSHDB
```

---

## Session consistency

When `DECEPTION_MODE=generative`, DeceptivGuard injects up to 3 prior fabricated responses from the same session as `[PRIOR FABRICATED CONTEXT]`. The LLM is instructed to match overlapping values exactly — same credentials, same IPs, same names — so a multi-turn attacker receives consistent fabrications rather than contradictory details that might reveal the deception.

Only clean responses are recycled — entries containing refusal signals or fabrication-disclosure phrases are filtered out and never used as prior context.

> [!TIP]
> In generative mode, reviewing the full session history via [Get session history](api.md#get-session-history) shows the complete fabricated narrative served to the attacker across all turns.
