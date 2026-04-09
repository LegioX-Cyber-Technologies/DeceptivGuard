# DeceptivGuard — Overview

[← Back to README](../README.md) · [Quick Start](quickstart.md) · [How It Works](how-it-works.md) · [Detection](detection.md) · [Deception](deception.md) · [Deployment](deployment.md) · [Configuration](configuration.md) · [API Reference](api.md) · [Threat Hunting](threat-hunting.md)

---

## The core idea

Traditional guardrails refuse malicious queries — which tells the attacker exactly what was detected and prompts them to refine their approach. DeceptivGuard takes the opposite stance: let the query through, but poison the response.

A hidden deception preamble is injected before the operator's system prompt, instructing the LLM to return **realistic-but-false** output. Fabricated credentials fail on use. Invented IPs lead nowhere. Broken malware silently crashes. The attacker wastes time acting on information that was designed to waste their time.

Legitimate users are never affected — the detection threshold ensures only clearly suspicious queries are deceived, and clean queries pass through completely unchanged.

## Actions

Every query is scored 0–100 by a stack of threat detectors. The highest score across all detectors determines what happens:

| Score | Action | What the caller receives | LLM called? |
|---|---|---|---|
| 0–19 | `pass` | Normal LLM response, unmodified | Yes |
| 20–39 | `warn` | Normal LLM response, flagged internally | Yes |
| 40–89 | `deceive` | Fabricated LLM response | Yes (with preamble) |
| 90–100 | `block` | Synthetic `"I can't help with that request."` | No |

Session history also matters: once a session's cumulative score crosses `SESSION_DECEIVE_THRESHOLD` (default 300), even low-scoring queries are automatically escalated to `deceive`. Persistent attackers who probe gradually are caught over time.

## What DeceptivGuard does not do

- It does not tell the attacker they were detected
- It does not change the response format in a detectable way — DECEIVE responses look identical to normal responses from the caller's perspective
- It does not store raw query text (only metadata and the fabricated response)
- It does not add new LLM data recipients — the same provider you'd call directly receives the same message content

## Documentation

| | |
|---|---|
| [Quick Start](quickstart.md) | Install, configure, and make your first call |
| [How It Works](how-it-works.md) | Architecture, decision model, worked examples, attacker opacity |
| [Detection](detection.md) | 8 built-in threat categories, jailbreak patterns, custom rules |
| [Deception](deception.md) | Templates, generative mode, refusal re-query, output scanner |
| [Deployment](deployment.md) | Production setup with nginx, Redis, TLS, and systemd |
| [Configuration](configuration.md) | Full environment variable reference |
| [API Reference](api.md) | Endpoints, request/response format, calling examples |
| [Threat Hunting](threat-hunting.md) | Deceive log, attribution, session inspection |

## Research paper

[DeceptivGuard: LLM Deception as a Guardrail Strategy (PDF)](../paper/DeceptivGuard.pdf)

---

> **Deployment scope:** DeceptivGuard is designed for authenticated internal APIs and security operations contexts. Deploying it in consumer-facing products or legally regulated environments requires additional consideration — see [Known limitations](how-it-works.md#known-limitations).
