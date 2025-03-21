# ruff: noqa: PD901

from unittest.mock import patch

import pandas as pd
import pytest
from sqlalchemy import create_engine

from lambdas.utils.aws.athena import AthenaClient


@pytest.fixture(autouse=True)
def _test_env(monkeypatch):
    monkeypatch.setenv("WORKSPACE", "test")
    monkeypatch.setenv("SENTRY_DSN", "None")
    monkeypatch.setenv("AWS_ATHENA_WORK_GROUP", "default")
    monkeypatch.setenv("AWS_ATHENA_DATABASE", "my-athena-db")


@pytest.fixture
def mocked_engine():
    engine = create_engine("sqlite:///:memory:")
    with patch.object(AthenaClient, "get_athena_sqlalchemy_engine") as mocked_method:
        mocked_method.return_value = engine
        yield engine


@pytest.fixture
def mocked_pandas_read_sql_query():
    df = pd.DataFrame(
        [
            {"key": "data/horse.txt", "checksum_algorithm": "SHA256"},
            {"key": "data/zebra.txt", "checksum_algorithm": "SHA256"},
        ]
    )
    with patch.object(pd, "read_sql_query") as mocked_method:
        mocked_method.return_value = df
        yield df
