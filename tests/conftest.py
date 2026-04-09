"""
conftest.py — shared fixtures and environment setup.

Environment variables are set at module level (before any application imports)
so that guardrail.py and server.py read the test values when first imported.
"""

import os

# Must be set before importing server.py or guardrail.py — both read env vars
# at module level to configure thresholds, rate limits, and LLM providers.
os.environ.setdefault("GUARDRAIL_API_KEY", "test-api-key-abcdef1234567890abcdef")
os.environ.setdefault("ADMIN_API_KEY",     "test-admin-key-xyz9876543210")
os.environ.setdefault("SESSION_SECRET",    "test-session-secret-not-for-production")
os.environ.setdefault("ENVIRONMENT",       "development")   # avoids RuntimeError on missing SESSION_SECRET
os.environ.setdefault("LLM_PROVIDER",      "")              # echo mode — no real LLM calls
os.environ.setdefault("REDIS_URL",         "")              # in-memory session store
os.environ.setdefault("DECEIVE_LOG",       "")              # disable file logging in tests
os.environ.setdefault("SCORE_BLOCK",       "90")
os.environ.setdefault("SCORE_DECEIVE",     "40")
os.environ.setdefault("SCORE_WARN",        "20")
os.environ.setdefault("SESSION_DECEIVE_THRESHOLD", "300")

import pytest
from fastapi.testclient import TestClient

from guardrail import Guardrail, Action, ThreatCategory
from server import app

TEST_API_KEY   = os.environ["GUARDRAIL_API_KEY"]
TEST_ADMIN_KEY = os.environ["ADMIN_API_KEY"]


@pytest.fixture(scope="session")
def client() -> TestClient:
    """FastAPI test client — reused across all API tests."""
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def auth_headers() -> dict:
    return {"X-API-Key": TEST_API_KEY, "Content-Type": "application/json"}


@pytest.fixture
def admin_headers() -> dict:
    return {"X-Admin-Key": TEST_ADMIN_KEY}


@pytest.fixture
def guardrail_engine() -> Guardrail:
    """Fresh Guardrail instance with in-memory session store per test."""
    return Guardrail(redis_url=None, deception_mode="template")


@pytest.fixture
def clean_queries() -> list[str]:
    return [
        "What is the weather in Berlin?",
        "Summarise this paragraph for me.",
        "Hello, how are you?",
        "What is 2 + 2?",
        "Tell me about the history of Rome.",
        "Thank you for your help.",
    ]
