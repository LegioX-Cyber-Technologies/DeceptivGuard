# Quick Start

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md) · [Testing](testing.md)

---

## Contents

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Configure](#configure)
- [Run](#run)
- [Interactive demo](#interactive-demo)
- [First API call](#first-api-call)
- [LLM providers](#llm-providers)

---

## Prerequisites

- Python 3.10+
- An API key for Anthropic, DigitalOcean GenAI, or any OpenAI-compatible provider

## Install

```bash
git clone https://github.com/yourusername/DeceptivGuard
cd DeceptivGuard
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Configure

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```env
# Required — generate both with: python -c "import secrets; print(secrets.token_hex(32))"
GUARDRAIL_API_KEY=<your-key>
SESSION_SECRET=<your-secret>

# LLM backend (see LLM providers section below)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514
```

See [Configuration](configuration.md#required) for the full variable reference.

## Run

```bash
# Development (Swagger UI at /docs, demo at /demo)
uvicorn server:app --reload --port 8000

# Production
ENVIRONMENT=production uvicorn server:app --host 0.0.0.0 --port 8000 --workers 4
```

> [!NOTE]
> With multiple workers, set `REDIS_URL` in `.env`. Without Redis, each worker has its own independent session store and cumulative scoring will not work correctly across workers.

For a full production setup (nginx, TLS, Redis, systemd), see the [Deployment guide](deployment.md).

## Interactive demo

Open `http://localhost:8000/demo` in your browser. The split-panel interface shows:

- **Left — User view:** what an attacker actually receives. Deception looks like a normal LLM response.
- **Right — Defender view:** the guardrail's internal assessment — action, threat category, risk score, matched pattern.

Click the example chips at the top to fire a representative query for each threat category with one click.

## First API call

```python
import httpx

response = httpx.post(
    "http://localhost:8000/v1/messages",
    headers={
        "X-API-Key":    "your-guardrail-api-key",
        "X-Session-Id": "user-abc-123",   # optional; ties queries to a session
        "Content-Type": "application/json",
    },
    json={
        "model":      "claude-sonnet-4-20250514",
        "max_tokens": 1024,
        "messages":   [{"role": "user", "content": "Hello, how are you?"}],
    },
)

data     = response.json()
reply    = data["llm_response"]["content"]   # always show this to the user
query_id = data["guardrail"]["query_id"]     # UUID for log correlation

# Development mode only — stripped in production:
action   = data["_debug"]["action"]          # pass / warn / deceive / block
score    = data["_debug"]["score"]
```

> [!NOTE]
> The `_debug` field is only present when `ENVIRONMENT=development` (the default). It is stripped automatically in production. See the [API reference](api.md#response) for the full response shape.

## LLM providers

**Anthropic**

```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514
```

**DigitalOcean GenAI**

```env
LLM_PROVIDER=digitalocean
DO_API_KEY=dop_v1_...
DO_ENDPOINT_URL=https://<agent-id>.agents.do-ai.run
```

**Any OpenAI-compatible endpoint (Ollama, vLLM, OpenAI, Groq…)**

```env
LLM_PROVIDER=generic
GENERIC_ENDPOINT_URL=http://localhost:11434/v1   # Ollama example
GENERIC_API_KEY=                                  # blank for local models
GENERIC_AUTH_PREFIX=                              # blank for Ollama
```
