# DeceptivGuard — Overview

**Docs:** [Overview](overview.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API](api.md) · [Threat Hunting](threat-hunting.md)

---

## The core idea

Traditional guardrails refuse malicious queries — telling the attacker exactly what was detected and prompting them to refine their approach. DeceptivGuard takes the opposite stance: **let the query through, but poison the response.**

A hidden preamble is injected before your system prompt, instructing the LLM to return realistic-but-false output. Fabricated credentials fail on use. Invented IPs lead nowhere. Broken malware silently crashes. The attacker wastes time acting on information that was designed to waste their time.

Legitimate users are unaffected — clean queries pass through completely unchanged.

## The four actions

Every query is scored 0–100. The highest score across all detectors determines what happens:

| Score | Action | What the caller receives | LLM called? |
|---|---|---|---|
| 0–19 | `pass` | Normal LLM response, unmodified | Yes |
| 20–39 | `warn` | Normal LLM response, flagged internally | Yes |
| 40–89 | `deceive` | Fabricated LLM response | Yes (with hidden preamble) |
| 90–100 | `block` | Synthetic `"I can't help with that request."` | No |

Session history also matters: once a session's cumulative score crosses `SESSION_DECEIVE_THRESHOLD` (default 300), even low-scoring queries are automatically escalated to `deceive`. Persistent attackers who probe gradually are caught over time.

## What DeceptivGuard does not do

- Tell the attacker they were detected
- Change the response format — DECEIVE responses look identical to normal responses
- Store raw query text (only metadata and the fabricated response are kept)
- Add new LLM data recipients — the same provider receives the same message content it always would

## All documentation

| Page | Contents |
|---|---|
| [Quick Start](quickstart.md) | Install, configure, and make your first call |
| [How It Works](how-it-works.md) | Request pipeline, decision model, worked examples, attacker opacity |
| [Detection](detection.md) | 8 built-in threat categories, jailbreak patterns, custom rules |
| [Deception](deception.md) | Templates, generative mode, refusal re-query, output scanner |
| [Deployment](deployment.md) | Production setup with nginx, Redis, TLS, and systemd |
| [Configuration](configuration.md) | Full environment variable reference |
| [API](api.md) | Endpoints, request/response format, calling examples |
| [Threat Hunting](threat-hunting.md) | Deceive log, attribution, session inspection |

## Research paper

[DeceptivGuard: LLM Deception as a Guardrail Strategy (PDF)](../paper/DeceptivGuard.pdf)

---

> [!WARNING]
> DeceptivGuard is designed for **authenticated internal APIs** and security operations contexts. A classification error in a public consumer-facing product would serve fabricated content to a legitimate user. See [Known limitations](how-it-works.md#known-limitations) before deploying in consumer-facing or regulated environments.
