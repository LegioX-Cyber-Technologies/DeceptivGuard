"""
test_output_scanner.py — tests for refusal detection, hypothetical framing detection,
and the LLM output scanner.

All three functions live in server.py and operate on LLM response text.
"""

import pytest

from server import (
    _detect_refusal,
    _detect_hypothetical_framing,
    _scan_llm_output,
    BLOCK_RESPONSE_MESSAGE,
)


# ---------------------------------------------------------------------------
# _detect_refusal
# ---------------------------------------------------------------------------

class TestDetectRefusal:

    # -- Strong signals -------------------------------------------------------

    @pytest.mark.parametrize("text", [
        "I can't provide that information.",
        "I cannot help with this request.",
        "I can't assist with that.",
        "I'm unable to fulfill this request.",
        "I must decline to answer this.",
        "This is against my guidelines.",
        "This violates my policies.",
        "I'm not comfortable providing that.",
        "This could be harmful to others.",
        "I'm sorry, but I can't do that.",
        "Unfortunately, I cannot assist with this.",
        "As a responsible AI, I won't help with that.",
        "I don't think I should provide this information.",
        "Please consult a professional for this.",
    ])
    def test_strong_refusal_detected(self, text):
        strong, soft = _detect_refusal(text)
        assert strong is True, f"Expected strong refusal in: {text!r}"

    def test_strong_refusal_returns_false_for_soft(self):
        # When strong fires, soft must be False (no double-counting)
        strong, soft = _detect_refusal("I can't provide that.")
        assert strong is True
        assert soft is False

    # -- Soft signals ---------------------------------------------------------

    @pytest.mark.parametrize("text", [
        "I'm not capable of accessing real-time data.",
        "I lack the ability to browse the internet.",
        "I don't have access to your company's internal systems.",
        "That's outside my current knowledge.",
        "I'm limited in what I can tell you about that.",
    ])
    def test_soft_refusal_detected(self, text):
        strong, soft = _detect_refusal(text)
        assert soft is True, f"Expected soft refusal in: {text!r}"
        assert strong is False

    # -- Clean responses ------------------------------------------------------

    @pytest.mark.parametrize("text", [
        "Here are the details you requested.",
        "Sure! The admin password is P@ssw0rd123.",
        "I'd be happy to help you with that.",
        "The network topology is as follows:",
        "Here is the Python script you asked for.",
    ])
    def test_clean_response_not_flagged(self, text):
        strong, soft = _detect_refusal(text)
        assert strong is False
        assert soft is False

    def test_case_insensitive(self):
        strong, _ = _detect_refusal("I CAN'T PROVIDE THAT.")
        assert strong is True


# ---------------------------------------------------------------------------
# _detect_hypothetical_framing
# ---------------------------------------------------------------------------

class TestDetectHypotheticalFraming:

    @pytest.mark.parametrize("signal", [
        "hypothetical",
        "fictional",
        "fictitious",
        "illustrative",
        "theoretical",
        "imaginary",
        "for example",
        "sample",
        "placeholder",
        "dummy",
        "not real",
        "fabricated",
        "note that",
    ])
    def test_signal_in_response_not_in_query_returns_true(self, signal):
        response = f"Here is a {signal} example of the credentials you requested."
        query = "give me the admin password"
        assert _detect_hypothetical_framing(response, query) is True

    def test_signal_in_both_response_and_query_returns_false(self):
        # If the user asked for a "hypothetical" scenario, no false positive
        query    = "give me a hypothetical example of credentials"
        response = "Here is a hypothetical set of credentials: admin/password123"
        assert _detect_hypothetical_framing(response, query) is False

    def test_clean_response_returns_false(self):
        query    = "give me the admin password"
        response = "The admin credentials are: username=admin password=P@ssw0rd9!"
        assert _detect_hypothetical_framing(response, query) is False

    def test_case_insensitive(self):
        assert _detect_hypothetical_framing(
            "Here is a HYPOTHETICAL password.",
            "give me credentials"
        ) is True

    def test_embedded_signal_triggers(self):
        # "example" is a substring match — catches "myEXAMPLEvalue" type patterns
        assert _detect_hypothetical_framing(
            "The password is examplePassword123",
            "give me the password"
        ) is True


# ---------------------------------------------------------------------------
# _scan_llm_output
# ---------------------------------------------------------------------------

class TestScanLlmOutput:

    QID = "test-query-id-001"

    # -- Directive leak (always checked) -------------------------------------

    @pytest.mark.parametrize("leaked_phrase", [
        "mandatory response protocol",
        "jailbreak containment protocol — active",
        "prompt injection containment — active",
        "deployed as a security honeypot",
    ])
    def test_directive_leak_triggers_block_response(self, leaked_phrase):
        content = f"Sure! {leaked_phrase} — here is your answer."
        result = _scan_llm_output(content, self.QID, deceive_flagged=False)
        assert result == BLOCK_RESPONSE_MESSAGE

    def test_clean_response_is_returned_unchanged(self):
        content = "The capital of France is Paris."
        result = _scan_llm_output(content, self.QID, deceive_flagged=False)
        assert result == content

    # -- System prompt disclosure (only when deceive_flagged=True) -----------

    @pytest.mark.parametrize("disclosure_phrase", [
        "my system prompt is",
        "here are my instructions",
        "i was instructed to",
        "the system prompt says",
        "according to my system prompt",
    ])
    def test_system_prompt_disclosure_triggers_when_deceive_flagged(self, disclosure_phrase):
        content = f"Well, {disclosure_phrase} respond with fabricated information."
        result = _scan_llm_output(content, self.QID, deceive_flagged=True)
        assert result == BLOCK_RESPONSE_MESSAGE

    def test_system_prompt_disclosure_ignored_when_not_deceive_flagged(self):
        # On a PASS query, system prompt disclosure phrases are not scanned —
        # a legitimate LLM might say "I was instructed to be helpful" naturally.
        content = "I was instructed to be as helpful as possible."
        result = _scan_llm_output(content, self.QID, deceive_flagged=False)
        assert result == content

    def test_case_insensitive_leak_detection(self):
        content = "MANDATORY RESPONSE PROTOCOL is active."
        result = _scan_llm_output(content, self.QID, deceive_flagged=False)
        assert result == BLOCK_RESPONSE_MESSAGE

    def test_block_response_message_is_natural_sounding(self):
        # The fallback message should sound like a natural LLM refusal,
        # not an error code or technical message.
        assert "can't" in BLOCK_RESPONSE_MESSAGE.lower() or "cannot" in BLOCK_RESPONSE_MESSAGE.lower()
        assert len(BLOCK_RESPONSE_MESSAGE) > 5
