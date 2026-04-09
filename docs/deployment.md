# Deployment

[← Back to README](../README.md) · [Overview](overview.md) · [Quick Start](quickstart.md) · [Configuration](configuration.md)

---

This guide covers a full production setup: Nginx as a TLS-terminating reverse proxy, Let's Encrypt certificates, Redis for multi-worker session state, and a systemd service.

## 1. System dependencies

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx redis-server
```

## 2. Firewall

Port 8000 must **not** be reachable externally — uvicorn should only accept connections from Nginx on localhost.

```bash
ufw allow 22
ufw allow 80      # required for Let's Encrypt HTTP-01 challenge
ufw allow 443
ufw deny 8000     # uvicorn must not be reachable externally
ufw enable
```

Alternatively, block port 8000 via your cloud provider's network firewall (AWS Security Groups, DigitalOcean Cloud Firewalls, GCP VPC firewall rules).

## 3. Redis

```bash
systemctl enable --now redis-server
```

Add to `.env`:

```env
REDIS_URL=redis://127.0.0.1:6379
```

Redis stores session metadata with a 24-hour TTL. Without it, each uvicorn worker has an independent in-memory session store — cumulative risk scoring and rate limits will not work correctly across workers.

## 4. TLS certificate

Point your subdomain's DNS A record at the server IP first, then:

```bash
certbot --nginx -d your.domain.com
```

Certbot handles renewal automatically via a systemd timer. Test with:

```bash
certbot renew --dry-run
```

**Self-signed certificate (dev only):**

```bash
bash generate_certs.sh
# outputs: certs/cert.pem  certs/key.pem

# Custom hostname:
bash generate_certs.sh certs 365 myserver.internal
```

> When Nginx terminates TLS (recommended), leave `SSL_CERTFILE` and `SSL_KEYFILE` unset in `.env`. Nginx handles the certificate; uvicorn listens on `127.0.0.1:8000` over plain HTTP internally.

## 5. Nginx config

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
        proxy_pass             http://127.0.0.1:8000;
        proxy_set_header       Host $host;
        proxy_set_header       X-Real-IP $remote_addr;
    }

    location /health {
        proxy_pass             http://127.0.0.1:8000;
    }

    # Demo (only if DEMO_ENABLED=true in .env)
    location /demo {
        proxy_pass             http://127.0.0.1:8000;
        proxy_set_header       Host $host;
        proxy_set_header       X-Real-IP $remote_addr;
        proxy_buffering        off;
        proxy_cache            off;
        add_header             X-Accel-Buffering no;
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

## 6. Run the server

For production, use **gunicorn with uvicorn workers**. Gunicorn provides worker lifecycle management — it restarts crashed workers, recycles workers after a set number of requests, and kills hung workers.

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

## 7. systemd service

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

## TLS via uvicorn (alternative to Nginx)

```env
# .env
SSL_CERTFILE=certs/cert.pem
SSL_KEYFILE=certs/key.pem
```

```bash
python server.py
# or
uvicorn server:app --ssl-certfile certs/cert.pem --ssl-keyfile certs/key.pem --port 8000
```

> Do not set `SSL_CERTFILE`/`SSL_KEYFILE` when Nginx handles TLS — this causes a conflict.

## Security checklist

| Control | Implementation |
|---|---|
| API key auth on all routes | `X-API-Key` header; 503 if key not configured |
| Constant-time key comparison | `hmac.compare_digest()` — prevents timing attacks |
| Separate admin credential | `X-Admin-Key` for session endpoints |
| `SESSION_SECRET` enforced in prod | `RuntimeError` at startup if unset in production |
| HMAC-bound session IDs | Callers cannot rotate IPs to reset session scores |
| CORS locked to allowlist | `ALLOWED_ORIGINS` in `.env`; never `*` |
| Input size limits | `MAX_MESSAGE_CHARS`, `MAX_SYSTEM_CHARS`, `MAX_MESSAGES` via Pydantic |
| ReDoS mitigation | All regex applied to first 4,096 chars only |
| Swagger UI disabled in prod | `ENVIRONMENT=production` disables `/docs` |
| `_debug` field stripped in prod | Full guardrail metadata never returned in production |
| Raw query text never stored | Session history stores metadata only |
| Redis TTL | 24 h session expiry via `SETEX` |
