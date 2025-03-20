# ruff: noqa: N806
from unittest.mock import patch

import pytest

from lambdas.config import Config, configure_sentry


def test_config_configures_sentry_if_dsn_present(caplog, monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://1234567890@00000.ingest.sentry.io/123456")
    configure_sentry()
    assert (
        "Sentry DSN found, exceptions will be sent to Sentry with env=test" in caplog.text
    )


def test_config_doesnt_configure_sentry_if_dsn_not_present(caplog, monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    configure_sentry()
    assert "No Sentry DSN found, exceptions will not be sent to Sentry" in caplog.text


def test_config_env_var_dot_notation(monkeypatch):
    CONFIG = Config()
    assert CONFIG.WORKSPACE == "test"


def test_config_optional_env_var_dot_notation_fails_if_not_defined(monkeypatch):
    CONFIG = Config()
    with pytest.raises(
        AttributeError, match="'FRUIT' not a valid configuration variable"
    ):
        _ = CONFIG.FRUIT


def test_config_optional_env_var_dot_notation_success_if_defined(monkeypatch):
    monkeypatch.setenv("FRUIT", "apple")
    with patch.object(Config, "OPTIONAL_ENV_VARS", ("FRUIT",)):
        CONFIG = Config()
        assert CONFIG.FRUIT == "apple"
