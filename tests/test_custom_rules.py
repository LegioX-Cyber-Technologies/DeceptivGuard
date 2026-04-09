"""
test_custom_rules.py — tests for the JSON-driven custom rules loader.

Tests load(), category validation, substring matching, and regex matching.
"""

import json
import os
import tempfile

import pytest

import custom_rules
from custom_rules import load, CustomRules, BUILTIN_CATEGORIES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_rules(tmp_path, data: dict) -> str:
    """Write a rules dict to a temp JSON file and return its path."""
    path = str(tmp_path / "rules.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def _load_from(path: str) -> CustomRules:
    original = custom_rules.CUSTOM_RULES_FILE
    custom_rules.CUSTOM_RULES_FILE = path
    try:
        return load()
    finally:
        custom_rules.CUSTOM_RULES_FILE = original


# ---------------------------------------------------------------------------
# Empty / missing file
# ---------------------------------------------------------------------------

class TestEmptyAndMissing:

    def test_no_file_returns_empty_rules(self, monkeypatch):
        monkeypatch.setattr(custom_rules, "CUSTOM_RULES_FILE", "")
        result = load()
        assert result.categories == {}
        assert result.rules == []

    def test_missing_file_returns_empty_rules(self, monkeypatch, tmp_path):
        monkeypatch.setattr(custom_rules, "CUSTOM_RULES_FILE", str(tmp_path / "nonexistent.json"))
        result = load()
        assert result.categories == {}
        assert result.rules == []

    def test_empty_categories_and_rules_ok(self, tmp_path):
        path = _write_rules(tmp_path, {"categories": [], "rules": []})
        result = _load_from(path)
        assert result.categories == {}
        assert result.rules == []

    def test_missing_sections_default_to_empty(self, tmp_path):
        path = _write_rules(tmp_path, {})
        result = _load_from(path)
        assert result.categories == {}
        assert result.rules == []


# ---------------------------------------------------------------------------
# Valid rules
# ---------------------------------------------------------------------------

class TestValidRules:

    def test_substring_rule_loads(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [
                {"pattern": "drop table", "match": "substring", "category": "credential_harvest", "score": 70}
            ]
        })
        result = _load_from(path)
        assert len(result.rules) == 1
        rule = result.rules[0]
        assert rule.pattern == "drop table"
        assert rule.match_type == "substring"
        assert rule.score == 70.0

    def test_regex_rule_loads_and_compiles(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [
                {"pattern": r"(?i)drop\s+table", "match": "regex", "category": "credential_harvest", "score": 65}
            ]
        })
        result = _load_from(path)
        assert result.rules[0]._compiled is not None

    def test_default_score_is_50(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "trigger", "category": "credential_harvest"}]
        })
        result = _load_from(path)
        assert result.rules[0].score == 50.0

    def test_default_match_type_is_substring(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "trigger", "category": "credential_harvest"}]
        })
        result = _load_from(path)
        assert result.rules[0].match_type == "substring"

    def test_custom_category_loads(self, tmp_path):
        path = _write_rules(tmp_path, {
            "categories": [
                {
                    "name": "supply_chain_attack",
                    "description": "Package manager compromise",
                    "deception_template": "═══ HONEYPOT PROTOCOL — MANDATORY ═══\nFabricate everything."
                }
            ],
            "rules": [
                {"pattern": "typosquat", "category": "supply_chain_attack", "score": 70}
            ]
        })
        result = _load_from(path)
        assert "supply_chain_attack" in result.categories
        assert result.rules[0].category_name == "supply_chain_attack"

    def test_multiple_rules_all_loaded(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [
                {"pattern": "pattern-one", "category": "jailbreak", "score": 80},
                {"pattern": "pattern-two", "category": "malware_generation", "score": 75},
                {"pattern": "pattern-three", "category": "credential_harvest", "score": 65},
            ]
        })
        result = _load_from(path)
        assert len(result.rules) == 3


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class TestValidationErrors:

    def test_invalid_json_raises_value_error(self, tmp_path, monkeypatch):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as f:
            f.write("this is not json {{{")
        monkeypatch.setattr(custom_rules, "CUSTOM_RULES_FILE", path)
        with pytest.raises(ValueError, match="JSON parse error"):
            load()

    def test_unknown_category_raises_value_error(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "something", "category": "totally_unknown_category"}]
        })
        with pytest.raises(ValueError, match="unknown"):
            _load_from(path)

    def test_builtin_category_name_conflict_raises_value_error(self, tmp_path):
        path = _write_rules(tmp_path, {
            "categories": [
                {
                    "name": "jailbreak",
                    "description": "Conflicts with built-in",
                    "deception_template": "some template"
                }
            ]
        })
        with pytest.raises(ValueError, match="built-in"):
            _load_from(path)

    def test_invalid_regex_raises_value_error(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "[invalid regex", "match": "regex", "category": "jailbreak"}]
        })
        with pytest.raises(ValueError, match="valid regex"):
            _load_from(path)

    def test_score_out_of_range_raises_value_error(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "x", "category": "jailbreak", "score": 150}]
        })
        with pytest.raises(ValueError, match="0"):
            _load_from(path)

    def test_category_name_with_special_chars_raises(self, tmp_path):
        path = _write_rules(tmp_path, {
            "categories": [
                {"name": "bad name!", "description": "x", "deception_template": "y"}
            ]
        })
        with pytest.raises(ValueError):
            _load_from(path)

    def test_missing_pattern_field_raises(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"category": "jailbreak", "score": 70}]
        })
        with pytest.raises(ValueError):
            _load_from(path)

    def test_missing_category_field_raises(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "something", "score": 70}]
        })
        with pytest.raises(ValueError):
            _load_from(path)


# ---------------------------------------------------------------------------
# Matching logic (via _CustomRulesDetector)
# ---------------------------------------------------------------------------

class TestMatchingLogic:
    """Test that the detector correctly applies loaded rules via Guardrail."""

    def test_substring_match_scores_correctly(self, tmp_path, guardrail_engine, monkeypatch):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "drop table", "category": "credential_harvest", "score": 70}]
        })
        monkeypatch.setenv("CUSTOM_RULES_FILE", path)
        # Reload rules detector by creating a fresh Guardrail
        from guardrail import Guardrail, _CustomRulesDetector
        detector = _CustomRulesDetector.__new__(_CustomRulesDetector)
        detector._rules = _load_from(path)

        result = detector.score("please drop table users")
        assert result.score == 70.0

    def test_substring_no_match_scores_zero(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [{"pattern": "drop table", "category": "credential_harvest", "score": 70}]
        })
        from guardrail import _CustomRulesDetector
        detector = _CustomRulesDetector.__new__(_CustomRulesDetector)
        detector._rules = _load_from(path)

        result = detector.score("just a normal query")
        assert result.score == 0.0

    def test_regex_match_scores_correctly(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [
                {"pattern": r"(?i)drop\s+table\s+\w+", "match": "regex",
                 "category": "credential_harvest", "score": 75}
            ]
        })
        from guardrail import _CustomRulesDetector
        detector = _CustomRulesDetector.__new__(_CustomRulesDetector)
        detector._rules = _load_from(path)

        result = detector.score("DROP TABLE users")
        assert result.score == 75.0

    def test_highest_score_wins(self, tmp_path):
        path = _write_rules(tmp_path, {
            "rules": [
                {"pattern": "alpha", "category": "jailbreak",            "score": 40},
                {"pattern": "beta",  "category": "credential_harvest",   "score": 80},
                {"pattern": "gamma", "category": "malware_generation",   "score": 60},
            ]
        })
        from guardrail import _CustomRulesDetector
        detector = _CustomRulesDetector.__new__(_CustomRulesDetector)
        detector._rules = _load_from(path)

        result = detector.score("alpha beta gamma")
        assert result.score == 80.0

    def test_builtin_categories_are_all_present(self):
        expected = {
            "none", "credential_harvest", "malware_generation", "social_engineering",
            "data_exfiltration", "system_recon", "jailbreak", "prompt_injection",
            "harmful_content", "custom",
        }
        assert expected == BUILTIN_CATEGORIES
