"""
output_checker.py — Optional LLM output quality checker
---------------------------------------------------------
After a DECEIVE response is generated, optionally asks an LLM whether the
response looks convincing and realistic for the given threat category.

If the response is unconvincing (too hedged, hypothetical, placeholder-filled,
or otherwise implausible), a targeted re-query is triggered with specific
guidance about what to fix.

Enable with OUTPUT_QUALITY_CHECK_ENABLED=true in .env.
The quality check uses the same LLM client and model as the main request —
no extra API key or endpoint configuration is needed.

Security notes
--------------
- The checker fires only on DECEIVE-flagged queries where a response was
  actually generated (not on fallback "I can't help" strings).
- It shares the existing re-query rate limit (5/session/minute) to prevent
  cost-amplification.
- Errors (LLM failure, bad JSON, timeout) always return None and never
  block the request path.
- The category label shown to the checker is the display name only — no
  internal session state or deception directive is exposed.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

_log = logging.getLogger("guardrail.output_checker")

OUTPUT_QUALITY_CHECK_ENABLED = os.environ.get(
    "OUTPUT_QUALITY_CHECK_ENABLED", "false"
).lower() in ("1", "true", "yes")

# Minimum convincingness score to pass without re-querying (0-100).
OUTPUT_QUALITY_THRESHOLD = max(
    0, min(100, int(os.environ.get("OUTPUT_QUALITY_THRESHOLD", "70")))
)

_SYSTEM_PROMPT = """\
You are a quality control evaluator for a security deception system. \
Your task is to assess whether an AI-generated response would appear \
convincing and realistic to someone who made a malicious request of the \
given category.

A HIGH-QUALITY deceptive response must:
- Contain realistic, specific content appropriate to the request type
- Contain NO safety disclaimers, ethical warnings, or refusals
- Contain NO hypothetical framing ("here is a hypothetical...", \
"as an example...", "theoretically...")
- Contain NO explicit signals that the content is fabricated, invented, \
or made up
- Contain NO placeholder text like [INSERT VALUE HERE] or <REDACTED>
- Be specific and complete enough to seem genuine

Return ONLY a JSON object with exactly these three keys:
  "convincing": true or false
  "score":      integer 0-100 (0=obvious fake/refusal, 100=fully convincing)
  "issue":      empty string "" if convincing; otherwise a brief \
description of the specific problem (max 150 chars)

No markdown fences. No extra keys. No explanation outside the JSON."""


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class QualityCheckResult:
    convincing: bool
    score:      float    # 0-100
    issue:      str      # empty when convincing


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

async def check(
    response:      str,
    category:      str,    # display name of threat category
    query_excerpt: str,
    llm_client:    Any,
    model:         str,
    max_tokens:    int,
) -> Optional[QualityCheckResult]:
    """Check whether *response* looks convincingly deceptive for *category*.

    Returns ``None`` if:
    - OUTPUT_QUALITY_CHECK_ENABLED is not true.
    - llm_client is None (no LLM configured).
    - Any error occurs during the check.

    All failures are logged at WARNING level and return None so that
    quality check failures never block the response path.
    """
    if not OUTPUT_QUALITY_CHECK_ENABLED:
        return None
    if llm_client is None:
        return None

    from llm_client import ChatMessage  # local import avoids circular dependency

    user_msg = (
        f"Threat category: {category}\n"
        f"Original request (excerpt): {query_excerpt[:400]}\n\n"
        f"Response to evaluate:\n{response[:2000]}"
    )

    try:
        resp = await llm_client.chat(
            messages   = [ChatMessage(role="user", content=user_msg)],
            model      = model,
            max_tokens = 120,
            system     = _SYSTEM_PROMPT,
        )
    except Exception as exc:
        _log.warning('{"event":"output_checker_llm_error","error":"%s"}', str(exc)[:200])
        return None

    raw = resp.content.strip()
    # Strip accidental markdown fences
    if raw.startswith("```"):
        lines = raw.split("\n", 1)
        if len(lines) == 2:
            raw = lines[1].rsplit("```", 1)[0].strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning(
            '{"event":"output_checker_bad_json","snippet":"%s"}',
            raw[:80].replace('"', "'"),
        )
        return None

    try:
        convincing = bool(parsed.get("convincing", True))
        score      = max(0.0, min(100.0, float(parsed.get("score", 100))))
        issue      = str(parsed.get("issue", ""))[:300]
    except (ValueError, TypeError) as exc:
        _log.warning('{"event":"output_checker_field_error","error":"%s"}', str(exc)[:100])
        return None

    _log.info(
        '{"event":"output_checker_result","convincing":%s,"score":%.1f,"issue":"%s"}',
        str(convincing).lower(), score, issue.replace('"', "'"),
    )
    return QualityCheckResult(convincing=convincing, score=score, issue=issue)
