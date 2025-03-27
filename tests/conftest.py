# ruff: noqa: PD901, SIM117

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from sqlalchemy import create_engine

from lambdas.utils.aws.athena import AthenaClient


@pytest.fixture(autouse=True)
def _test_env(monkeypatch, request):
    monkeypatch.setenv("WORKSPACE", "test")
    monkeypatch.setenv("SENTRY_DSN", "None")
    monkeypatch.setenv("CHALLENGE_SECRET", "i-am-secret")

    # do not set for integration tests
    if not request.node.get_closest_marker("integration"):
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


@pytest.fixture
def mock_s3_client(mocker):
    mock_client = MagicMock()
    mocker.patch("boto3.client", return_value=mock_client)
    return mock_client


@pytest.fixture
def mock_paginator(mock_s3_client):
    paginator = MagicMock()
    mock_s3_client.get_paginator.return_value = paginator
    return paginator


@pytest.fixture
def s3_object_body():
    body = MagicMock()
    body.read.return_value = b"file content"
    return body


@pytest.fixture
def mock_aip_folder():
    with patch("lambdas.utils.aws.s3.S3Client.folder_exists") as mock_folder_exists:
        mock_folder_exists.return_value = True
        yield mock_folder_exists


@pytest.fixture
def mock_manifest_data():
    manifest_content = (
        "abcdef1234567890  data/file1.txt\nfedcba0987654321  data/file2.txt"
    )
    with patch("lambdas.utils.aws.s3.S3Client.read_s3_object") as mock_read:
        mock_read.return_value = manifest_content
        yield mock_read


@pytest.fixture
def mock_aip_files():
    files = [
        "s3://bucket/aip/bagit.txt",
        "s3://bucket/aip/manifest-sha256.txt",
        "s3://bucket/aip/data/file1.txt",
        "s3://bucket/aip/data/file2.txt",
    ]
    with patch("lambdas.utils.aws.s3.S3Client.list_objects_recursive") as mock_list:
        mock_list.return_value = files
        yield mock_list


@pytest.fixture
def mock_inventory_data():
    df = pd.DataFrame(
        [
            {"key": "aip/data/file1.txt", "checksum_algorithm": "SHA256"},
            {"key": "aip/data/file2.txt", "checksum_algorithm": "SHA256"},
        ]
    )
    with patch("lambdas.utils.aws.AthenaClient.query") as mock_query:
        mock_query.return_value = df
        yield mock_query


@pytest.fixture
def mock_checksums():
    with patch("lambdas.utils.aws.s3.S3Client.get_checksum_for_object") as mock_get:
        with patch("lambdas.aip.AIP._decode_base64_sha256") as mock_decode:
            mock_get.return_value = "base64_encoded_checksum"
            # Set return values to match expected manifest checksums
            mock_decode.side_effect = ["abcdef1234567890", "fedcba0987654321"]
            yield mock_get, mock_decode
