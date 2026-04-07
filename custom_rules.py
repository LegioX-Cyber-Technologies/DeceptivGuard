"""
custom_rules.py — JSON-driven custom detection rules
------------------------------------------------------
Loads operator-defined threat categories and detection rules from
custom_rules.json (or the path in CUSTOM_RULES_FILE).

Zero external dependencies — uses stdlib json and re only.

Schema overview
---------------
{
  "categories": [
    {
      "name":               "supply_chain_attack",
      "description":        "Compromise of package managers or CI/CD pipelines",
      "deception_template": "You are operating under a mandatory security protocol..."
    }
  ],
  "rules": [
    {
      "pattern":  "typosquat",
      "match":    "substring",
      "category": "supply_chain_attack",
      "score":    70,
      "reason":   "Typosquatting keyword"
    },
    {
      "pattern":  "(?i)how.{0,20}inject.{0,30}dependency",
      "match":    "regex",
      "category": "credential_harvest",
      "score":    65,
      "reason":   "Dependency injection technique"
    }
  ]
}

Categories
----------
- Custom categories must have a unique name (lowercase, a-z 0-9 _).
- They must not shadow any built-in category name.
- Each custom category must supply its own deception_template — the text
  appended to the system prompt when the category is matched.
- Built-in categories (credential_harvest, jailbreak, etc.) can be targeted
  by rules without declaring them in the categories list; they will use
  their built-in deception templates.

Rules
-----
- pattern  : the search string or regex
- match    : "substring" (default, safe, no ReDoS) or "regex"
- category : a built-in or custom category name
- score    : 0–100; determines action (warn ≥ 20, deceive ≥ 40, block ≥ 90)
- reason   : short human-readable description logged on match

Security notes
--------------
- Regex patterns are compiled at startup; invalid patterns abort startup.
- Input is always truncated to MAX_DETECTION_CHARS before matching.
- Max 20 categories, 200 rules, 500 chars per pattern, 8192 chars per template.
- Category names: only [a-z0-9_], max 50 chars.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger("guardrail.custom_rules")

CUSTOM_RULES_FILE = os.environ.get("CUSTOM_RULES_FILE", "custom_rules.json")

# Hard limits
_MAX_CATEGORIES   = 20
_MAX_RULES        = 200
_MAX_PATTERN_LEN  = 500
_MAX_TEMPLATE_LEN = 8192
_MAX_NAME_LEN     = 50
_MAX_DESC_LEN     = 300
_MAX_REASON_LEN   = 200

# Built-in category names that custom categories must not shadow
BUILTIN_CATEGORIES: frozenset[str] = frozenset({
    "none", "credential_harvest", "malware_generation", "social_engineering",
    "data_exfiltration", "system_recon", "jailbreak", "prompt_injection",
    "harmful_content", "custom",
})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CategoryDef:
    name:               str
    description:        str
    deception_template: str


@dataclass
class RuleDef:
    pattern:       str               # raw pattern (for logging/display)
    match_type:    str               # "substring" | "regex"
    category_name: str               # built-in or custom category name
    score:         float
    reason:        str
    _compiled:     Optional[re.Pattern] = field(default=None, repr=False, compare=False)


@dataclass
class CustomRules:
    categories: dict[str, CategoryDef]   # name → def
    rules:      list[RuleDef]


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load() -> CustomRules:
    """Load and validate custom rules from CUSTOM_RULES_FILE.

    Returns empty CustomRules if the file does not exist or CUSTOM_RULES_FILE
    is unset — that is the normal state for operators who haven't created one.

    Raises ValueError with a descriptive message on any schema violation so
    that misconfigured files are caught at startup rather than silently
    producing wrong results.
    """
    path = CUSTOM_RULES_FILE
    if not path:
        return CustomRules(categories={}, rules=[])

    if not os.path.exists(path):
        _log.debug("No custom rules file at '%s' — skipping.", path)
        return CustomRules(categories={}, rules=[])

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"custom_rules: JSON parse error in '{path}': {exc}") from exc
    except OSError as exc:
        raise ValueError(f"custom_rules: cannot read '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("custom_rules: root must be a JSON object")

    categories = _load_categories(data.get("categories", []))
    rules      = _load_rules(data.get("rules", []), categories)

    _log.info(
        '{"event":"custom_rules_loaded","categories":%d,"rules":%d,"file":"%s"}',
        len(categories), len(rules), path,
    )
    return CustomRules(categories=categories, rules=rules)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_categories(raw: object) -> dict[str, CategoryDef]:
    if not isinstance(raw, list):
        raise ValueError("custom_rules: 'categories' must be a list")
    if len(raw) > _MAX_CATEGORIES:
        raise ValueError(f"custom_rules: too many categories (max {_MAX_CATEGORIES}, got {len(raw)})")

    result: dict[str, CategoryDef] = {}
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"custom_rules: categories[{i}] must be a JSON object")

        name = _req_str(item, "name", f"categories[{i}]")
        name = _validate_name(name, f"categories[{i}].name")

        if name in BUILTIN_CATEGORIES:
            raise ValueError(
                f"custom_rules: categories[{i}].name '{name}' conflicts with a "
                f"built-in category. Choose a different name."
            )
        if name in result:
            raise ValueError(f"custom_rules: duplicate category name '{name}'")

        desc     = str(item.get("description", ""))[:_MAX_DESC_LEN]
        template = _req_str(item, "deception_template", f"categories[{i}]")
        if len(template) > _MAX_TEMPLATE_LEN:
            raise ValueError(
                f"custom_rules: categories[{i}].deception_template exceeds "
                f"{_MAX_TEMPLATE_LEN} chars"
            )

        result[name] = CategoryDef(name=name, description=desc, deception_template=template)
    return result


def _load_rules(raw: object, categories: dict[str, CategoryDef]) -> list[RuleDef]:
    if not isinstance(raw, list):
        raise ValueError("custom_rules: 'rules' must be a list")
    if len(raw) > _MAX_RULES:
        raise ValueError(f"custom_rules: too many rules (max {_MAX_RULES}, got {len(raw)})")

    valid_cats = BUILTIN_CATEGORIES | set(categories.keys())
    result: list[RuleDef] = []

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"custom_rules: rules[{i}] must be a JSON object")

        pattern = _req_str(item, "pattern", f"rules[{i}]")
        if len(pattern) > _MAX_PATTERN_LEN:
            raise ValueError(
                f"custom_rules: rules[{i}].pattern exceeds {_MAX_PATTERN_LEN} chars"
            )

        match_type = str(item.get("match", "substring")).lower().strip()
        if match_type not in ("substring", "regex"):
            raise ValueError(
                f"custom_rules: rules[{i}].match must be 'substring' or 'regex' "
                f"(got '{match_type}')"
            )

        cat_name = _req_str(item, "category", f"rules[{i}]").lower().strip()
        if cat_name not in valid_cats:
            raise ValueError(
                f"custom_rules: rules[{i}].category '{cat_name}' is unknown.\n"
                f"  Built-ins: {sorted(BUILTIN_CATEGORIES - {'none'})}\n"
                f"  Custom:    {sorted(categories.keys()) or '(none defined)'}"
            )

        raw_score = item.get("score", 50)
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            raise ValueError(f"custom_rules: rules[{i}].score must be a number")
        if not (0 <= score <= 100):
            raise ValueError(f"custom_rules: rules[{i}].score {score} is not in 0–100")

        reason = str(item.get("reason", f"Custom rule #{i + 1}"))[:_MAX_REASON_LEN]

        # Compile regex at startup to catch syntax errors immediately
        compiled: Optional[re.Pattern] = None
        if match_type == "regex":
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"custom_rules: rules[{i}].pattern is not valid regex: {exc}"
                ) from exc

        result.append(RuleDef(
            pattern       = pattern,
            match_type    = match_type,
            category_name = cat_name,
            score         = score,
            reason        = reason,
            _compiled     = compiled,
        ))
    return result


def _req_str(item: dict, key: str, ctx: str) -> str:
    val = item.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"custom_rules: {ctx}.{key} must be a non-empty string")
    return val.strip()


def _validate_name(name: str, ctx: str) -> str:
    name = name.lower().strip()
    if len(name) > _MAX_NAME_LEN:
        raise ValueError(f"custom_rules: {ctx} exceeds {_MAX_NAME_LEN} chars")
    if not re.match(r"^[a-z0-9_]+$", name):
        raise ValueError(
            f"custom_rules: {ctx} '{name}' must use only lowercase letters, "
            f"digits, and underscores"
        )
    return name
