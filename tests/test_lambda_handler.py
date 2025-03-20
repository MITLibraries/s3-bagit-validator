import pytest

from lambdas import validator


def test_lambda_handler_missing_workspace_env_raises_error(monkeypatch):
    monkeypatch.delenv("WORKSPACE", raising=False)
    with pytest.raises(
        OSError,
        match="Missing required environment variables: WORKSPACE",
    ):
        validator.lambda_handler({})


def test_validator():
    assert validator.lambda_handler({}) == "You have successfully called this lambda!"
