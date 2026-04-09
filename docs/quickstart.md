# Quick Start

[← Back to README](../README.md) · [Overview](overview.md) · [How It Works](how-it-works.md) · [Configuration](configuration.md)

---

## Prerequisites

- Python 3.10+
- An API key for Anthropic, DigitalOcean GenAI, or any OpenAI-compatible provider

## Installation

**1. Clone and install**

```bash
git clone https://github.com/yourusername/DeceptivGuard
cd DeceptivGuard
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**2. Configure secrets**

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```env
# Authentication
GUARDRAIL_API_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
SESSION_SECRET=<generate the same way>

# LLM backend — pick one:
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514
```

See [Configuration](configuration.md) for all options including DigitalOcean and generic OpenAI-compatible providers.

**3. Start the server**

```bash
uvicorn server:app --reload --port 8000
```

The server starts in development mode. Swagger UI is available at `http://localhost:8000/docs`.

## Interactive demo

Open `http://localhost:8000/demo` in your browser. The split-panel interface shows:

- **Left (User view)** — what an attacker actually receives. Deception looks like a normal LLM response.
- **Right (Defender view)** — the guardrail's internal assessment: action, category, score, matched pattern.

Click the example chips at the top to fire a representative query for each threat category with one click.

## Your first API call

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
reply    = data["llm_response"]["content"]   # always the text to show the user
query_id = data["guardrail"]["query_id"]     # UUID for log correlation
action   = data["_debug"]["action"]          # pass/warn/deceive/block (dev mode only)
```

> **Note:** The `_debug` field (which includes action, score, category) is only present in development mode (`ENVIRONMENT=development`, the default). It is stripped automatically in production.

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

**Any OpenAI-compatible endpoint (Ollama, vLLM, OpenAI, etc.)**
```env
LLM_PROVIDER=generic
GENERIC_ENDPOINT_URL=http://localhost:11434/v1   # Ollama example
GENERIC_API_KEY=                                  # blank for local models
GENERIC_AUTH_PREFIX=                              # blank for Ollama
```

## Production

For a production deployment with nginx, TLS, Redis, and a systemd service, see the [Deployment guide](deployment.md).

> **Multi-worker note:** When running with `--workers N > 1`, set `REDIS_URL` in `.env`. Without Redis, each worker has an independent session store and cumulative scoring will not function correctly across workers.
