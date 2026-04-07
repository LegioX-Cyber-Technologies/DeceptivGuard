# Security Policy

## Supported versions

Only the latest version on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via GitHub's [Security Advisories](../../security/advisories/new) feature, or email the maintainer directly if that is not available.

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations you are aware of

You will receive an acknowledgement within 72 hours. Confirmed vulnerabilities will be patched and disclosed publicly once a fix is available.

## Scope

Reports are welcomed for:
- Authentication or authorisation bypass in `server.py`
- Session ID prediction or session fixation attacks
- Deception directive leakage to the caller
- ReDoS or denial-of-service via crafted input
- Information disclosure (real credentials, internal config, LLM system prompts) returned to callers
- Dependency vulnerabilities with a realistic exploit path in this deployment context

Out of scope:
- The LLM provider's own safety and security (report those to Anthropic, DigitalOcean, etc.)
- Social engineering or phishing of maintainers
- Issues that require physical access or a fully compromised host

## Ethical use

DeceptivGuard is a defensive tool. It is intended to protect systems by misleading attackers who probe LLM-backed services. Using this software to deceive legitimate users, operate without disclosure where legally required, or facilitate any illegal activity is outside the intended use and is not endorsed by the maintainers.
