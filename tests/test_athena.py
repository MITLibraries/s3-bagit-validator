# ruff: noqa: PD901

import os

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DatabaseError

from lambdas.utils.aws.athena import AthenaClient


def test_get_sqlalchemy_engine_created_from_config_success():
    athena_client = AthenaClient()
    engine = athena_client.engine
    assert isinstance(engine, Engine)
    assert engine.name == "awsathena"
    assert engine.url.database == os.getenv("AWS_ATHENA_DATABASE")


def test_perform_query_returns_dataframe(mocked_engine, mocked_pandas_read_sql_query):
    athena_client = AthenaClient()
    df = athena_client.query("""select * from foo;""")
    assert df.equals(mocked_pandas_read_sql_query)


# ----------------------------------------------------------------------------------
# Integration tests
# ----------------------------------------------------------------------------------


@pytest.mark.integration
def test_sqlalchemy_engine_connection_performs_query_success():
    """Test SQLAlchemy engine and connection can query AWS Athena.

    Requires
        - valid AWS credentials set
        - valid AWS_ATHENA_WORK_GROUP env var
    """
    engine = AthenaClient.get_athena_sqlalchemy_engine()
    with engine.connect() as conn:
        result = conn.execute(text("select 1 as x, 2 as y;"))
        row_dict = dict(result.mappings().first())
    assert row_dict == {"x": 1, "y": 2}


@pytest.mark.integration
def test_sqlalchemy_engine_connection_bad_workgroup_throws_error(monkeypatch):
    """Test invalid Athena workgroup throws error.

    Requires
        - valid AWS credentials set
    """
    monkeypatch.setenv("AWS_ATHENA_WORK_GROUP", "i-am-not-the-one")
    engine = AthenaClient.get_athena_sqlalchemy_engine()
    with engine.connect() as conn:  # noqa: SIM117
        with pytest.raises(DatabaseError, match="WorkGroup is not found."):
            _ = conn.execute(text("select 1 as x, 2 as y;"))


# NOTE WIP: anticipating more integration tests, with real Athena queries, as the
#   inventory querying logic is added
