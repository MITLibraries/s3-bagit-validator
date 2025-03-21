import pytest


@pytest.fixture(autouse=True)
def _test_env(monkeypatch):
    monkeypatch.setenv("WORKSPACE", "test")
    monkeypatch.setenv("SENTRY_DSN", "None")
