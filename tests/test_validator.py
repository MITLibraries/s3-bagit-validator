from importlib import reload

import pytest

from lambdas import validator


def test_validator_configures_sentry_if_dsn_present(caplog, monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://1234567890@00000.ingest.sentry.io/123456")
    reload(validator)
    assert (
        "Sentry DSN found, exceptions will be sent to Sentry with env=test" in caplog.text
    )


def test_validator_doesnt_configure_sentry_if_dsn_not_present(caplog, monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    reload(validator)
    assert "No Sentry DSN found, exceptions will not be sent to Sentry" in caplog.text


def test_lambda_handler_missing_workspace_env_raises_error(monkeypatch):
    monkeypatch.delenv("WORKSPACE", raising=False)
    with pytest.raises(RuntimeError) as error:
        validator.lambda_handler({})
    assert "Required env variable WORKSPACE is not set" in str(error)


def test_validator():
    assert validator.lambda_handler({}) == "You have successfully called this lambda!"
