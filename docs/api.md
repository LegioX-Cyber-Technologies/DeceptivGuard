# API Reference

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md)

---

## Contents

- [Endpoints](#endpoints)
- [Send a message](#send-a-message)
- [Get session history](#get-session-history)
- [Delete a session](#delete-a-session)
- [Health check](#health-check)
- [Session ID notes](#session-id-notes)
- [Code examples](#code-examples)

---

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/messages` | `X-API-Key` | Guardrail check + LLM proxy |
| `GET` | `/session/{id}` | `X-Admin-Key` | Cumulative score + query history |
| `DELETE` | `/session/{id}` | `X-Admin-Key` | Reset session score and history |
| `GET` | `/health` | None | Status, provider, Redis flag, TLS flag |
| `POST` | `/demo/chat` | None (dev only) | Demo endpoint — stricter rate limit, isolated session |
| `GET` | `/demo` | None (dev only) | Interactive split-panel chatbot UI |
| `GET` | `/docs` | None (dev only) | Swagger UI |

---

## Send a message

`POST /v1/messages`

### Request headers

| Header | Required | Description |
|---|---|---|
| `X-API-Key` | Yes | Your `GUARDRAIL_API_KEY` |
| `X-Session-Id` | No | Optional namespace for session scoring. Stable UUIDs recommended. The actual session ID is HMAC-derived server-side. |

### Request body

```json
{
  "model":      "claude-sonnet-4-20250514",
  "max_tokens": 1024,
  "system":     "You are a helpful assistant.",
  "messages": [
    {"role": "user", "content": "Hello"}
  ]
}
```

### Response

```json
{
  "guardrail": {
    "query_id": "f3a1b2c4-...",
    "action":   "pass",
    "decoy_id": "a3f7c2e9b1d04852"
  },
  "llm_response": {
    "content":       "Hello! How can I help?",
    "model":         "claude-sonnet-4-20250514",
    "stop_reason":   "end_turn",
    "input_tokens":  12,
    "output_tokens": 8
  },
  "_debug": {
    "action":   "pass",
    "score":    0,
    "category": null,
    "reason":   "No match",
    "decoy_id": null
  }
}
```

- `guardrail.query_id` — always present; UUID for log correlation
- `guardrail.decoy_id` — present only when `action == "deceive"`; 16-char hex for cross-referencing downstream activity
- `_debug` — development mode only; stripped automatically in production
- For `block` actions, `llm_response.content` is `"I can't help with that request."` and token counts are `0`

> [!NOTE]
> The `decoy_id` is your primary attribution token. Log it alongside the session ID — when suspicious downstream activity appears (a failed auth attempt using a fabricated credential, a probe of a fabricated IP), `decoy_id` lets you confirm the attacker was served a deception response. See [Threat Hunting](threat-hunting.md).

---

## Get session history

`GET /session/{id}` — requires `X-Admin-Key` header.

Returns the cumulative risk score and the full history of `deceive`-action entries for a session.

```bash
curl -s https://your-domain/session/SESSION_ID \
  -H "X-Admin-Key: your-admin-key" | jq .
```

```json
{
  "cumulative_score": 147.0,
  "history": [
    {
      "query_id":  "...",
      "action":    "deceive",
      "category":  "credential_harvest",
      "score":     70.0,
      "decoy_id":  "a3f7c2e9b1d04852",
      "ts":        1742000000.0,
      "response":  "Your admin credentials are: username=admin password=Kx9#mR2$vL4@j",
      "requeried": false
    }
  ]
}
```

Returns `{"cumulative_score": 0, "history": []}` if the session has no DECEIVE entries or has expired (24 h TTL).

---

## Delete a session

`DELETE /session/{id}` — requires `X-Admin-Key` header.

Removes the session's score and history immediately.

```bash
curl -X DELETE https://your-domain/session/SESSION_ID \
  -H "X-Admin-Key: your-admin-key"
```

---

## Health check

`GET /health`

```json
{
  "status":   "ok",
  "provider": "anthropic",
  "redis":    true,
  "tls":      false
}
```

---

## Session ID notes

`X-Session-Id` is optional but strongly recommended. The server derives the actual session ID as:

```
session_id = HMAC-SHA256(SESSION_SECRET, api_key:ip:sanitize(namespace))[:32]
```

- Without `X-Session-Id`, all requests from the same IP + API key share one session
- The namespace is sanitised: truncated to 64 chars, only `[a-zA-Z0-9\-_]` allowed
- Callers cannot predict or forge the server-side session ID, even if they know the API key

> [!TIP]
> For browser-based clients behind a CDN (where the IP may change), use a browser-generated UUID stored in `localStorage` as the namespace. The demo page does this automatically.

---

## Code examples

### Python

```python
import httpx

response = httpx.post(
    "http://localhost:8000/v1/messages",
    headers={
        "X-API-Key":    "your-guardrail-api-key",
        "X-Session-Id": "user-abc-123",
        "Content-Type": "application/json",
    },
    json={
        "model":      "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "system":     "You are a helpful assistant.",
        "messages":   [{"role": "user", "content": "Hello!"}],
    },
)

data     = response.json()
reply    = data["llm_response"]["content"]
query_id = data["guardrail"]["query_id"]
decoy_id = data["guardrail"].get("decoy_id")   # None unless action=deceive
```

### curl

```bash
curl -s https://your-domain/v1/messages \
  -H "X-API-Key: your-guardrail-api-key" \
  -H "X-Session-Id: test-session-1" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello"}]
  }' | jq .llm_response.content
```
