# Deployment

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md)

---

## Contents

- [System dependencies](#system-dependencies)
- [Firewall](#firewall)
- [Redis](#redis)
- [TLS certificate](#tls-certificate)
- [Nginx config](#nginx-config)
- [Run the server](#run-the-server)
- [systemd service](#systemd-service)
- [Security checklist](#security-checklist)

---

This guide covers a full production setup: Nginx as a TLS-terminating reverse proxy, Let's Encrypt certificates, Redis for multi-worker session state, and a systemd service.

## System dependencies

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx redis-server
```

## Firewall

Port 8000 must **not** be reachable externally — uvicorn should only accept connections from Nginx on localhost.

```bash
ufw allow 22
ufw allow 80      # required for Let's Encrypt HTTP-01 challenge
ufw allow 443
ufw deny 8000     # uvicorn must not be reachable externally
ufw enable
```

Alternatively, block port 8000 via your cloud provider's network firewall (AWS Security Groups, DigitalOcean Cloud Firewalls, GCP VPC firewall rules).

## Redis

```bash
systemctl enable --now redis-server
```

Add to `.env`:

```env
REDIS_URL=redis://127.0.0.1:6379
```

Redis stores session metadata with a 24-hour TTL. Without it, each worker process has an independent in-memory session store and cumulative risk scoring will not work correctly across workers.

## TLS certificate

Point your domain's DNS A record at the server IP first, then:

```bash
certbot --nginx -d your.domain.com
```

Certbot handles renewal automatically via a systemd timer. Test with:

```bash
certbot renew --dry-run
```

**Self-signed certificate (local/dev only):**

```bash
bash generate_certs.sh
# Custom hostname: bash generate_certs.sh certs 365 myserver.internal
```

> [!NOTE]
> When Nginx terminates TLS (recommended for production), leave `SSL_CERTFILE` and `SSL_KEYFILE` **unset** in `.env`. Nginx handles the certificate; uvicorn listens on `127.0.0.1:8000` over plain HTTP internally. Setting both causes a conflict.

## Nginx config

```nginx
server {
    listen 80;
    server_name your.domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your.domain.com;

    ssl_certificate     /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    location /v1/ {
        proxy_pass             http://127.0.0.1:8000;
        proxy_set_header       Host $host;
        proxy_set_header       X-Real-IP $remote_addr;
        proxy_set_header       X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header       X-Forwarded-Proto $scheme;
        proxy_read_timeout     120s;
        proxy_buffering        off;    # required for SSE streaming
        proxy_cache            off;
        add_header             X-Accel-Buffering no;
    }

    location /session/ {
        proxy_pass       http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000;
    }

    # Only needed when DEMO_ENABLED=true
    location /demo {
        proxy_pass       http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering  off;
        proxy_cache      off;
        add_header       X-Accel-Buffering no;
    }

    location / { return 404; }
}
```

```bash
nginx -t && systemctl reload nginx
```

If nginx cannot read the cert files:

```bash
chmod 755 /etc/letsencrypt/live/
chmod 755 /etc/letsencrypt/archive/
```

## Run the server

Use **gunicorn with uvicorn workers** for production. Gunicorn provides robust worker lifecycle management — restarting crashed workers, recycling them after a set number of requests to prevent memory leaks, and killing hung workers.

```bash
pip install gunicorn

ENVIRONMENT=production gunicorn server:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 127.0.0.1:8000 \
  --timeout 120 \
  --keep-alive 5 \
  --max-requests 1000 \
  --max-requests-jitter 100 \
  --access-logfile - \
  --error-logfile -
```

Worker count guideline: `(2 × CPU cores) + 1`. Check with `nproc`.

## systemd service

```ini
# /etc/systemd/system/deceptivguard.service
[Unit]
Description=DeceptivGuard
After=network.target redis.service

[Service]
User=www-data
WorkingDirectory=/path/to/DeceptivGuard
EnvironmentFile=/path/to/DeceptivGuard/.env
ExecStart=/path/to/DeceptivGuard/venv/bin/gunicorn server:app \
  --worker-class uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 127.0.0.1:8000 \
  --timeout 120 \
  --keep-alive 5 \
  --max-requests 1000 \
  --max-requests-jitter 100
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now deceptivguard
```

## Security checklist

| Control | Implementation |
|---|---|
| API key auth on all routes | `X-API-Key` header; 503 if key not configured |
| Constant-time comparison | `hmac.compare_digest()` on all key checks — prevents timing attacks |
| Separate admin credential | `X-Admin-Key` for session endpoints; falls back to `GUARDRAIL_API_KEY` if unset |
| `SESSION_SECRET` enforced in prod | `RuntimeError` at startup if unset in production |
| HMAC-bound session IDs | Callers cannot rotate IPs to reset session scores |
| CORS locked to allowlist | `ALLOWED_ORIGINS` in `.env`; never `*` |
| Input size limits | `MAX_MESSAGE_CHARS`, `MAX_SYSTEM_CHARS`, `MAX_MESSAGES` enforced via Pydantic |
| ReDoS mitigation | All regex applied to first 4,096 chars only |
| Swagger UI disabled in prod | `ENVIRONMENT=production` disables `/docs` and `/redoc` |
| `_debug` field stripped in prod | Full guardrail metadata never returned to callers in production |
| Raw query text never stored | Session history stores metadata only |
| Redis TTL | 24 h session expiry via `SETEX` |
| Error message sanitisation | LLM backend errors always return generic message — internal details never leaked |
