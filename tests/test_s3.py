# ruff: noqa: ARG002, D205

import base64
import hashlib
import random
import time

import pytest
from botocore.exceptions import ClientError

from lambdas.utils.aws.s3 import S3Client


class TestS3URIParsing:
    def test_parse_valid_s3_uri(self):
        bucket, key = S3Client.parse_s3_uri("s3://bucket/folder/file.txt")
        assert bucket == "bucket"
        assert key == "folder/file.txt"

    def test_parse_invalid_s3_uri(self):
        with pytest.raises(ValueError, match="Invalid S3 URI scheme"):
            S3Client.parse_s3_uri("http://bucket/folder/file.txt")

    def test_parse_s3_uri_empty_path(self):
        bucket, key = S3Client.parse_s3_uri("s3://bucket/")
        assert bucket == "bucket"
        assert key == ""


class TestFolderExists:
    def test_folder_exists_when_folder_present(self, mock_s3_client):
        mock_s3_client.list_objects_v2.return_value = {
            "Contents": [{"Key": "folder/file.txt"}]
        }
        assert S3Client.folder_exists("s3://bucket/folder/")

    def test_folder_exists_when_folder_absent(self, mock_s3_client):
        mock_s3_client.list_objects_v2.return_value = {}  # no 'Contents'
        assert not S3Client.folder_exists("s3://bucket/folder/")


class TestListObjectsRecursive:
    def test_list_objects_recursive_single_page(self, mock_s3_client, mock_paginator):
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "folder/file1.txt"},
                    {"Key": "folder/subfolder/"},  # folder should be skipped
                    {"Key": "folder/file2.txt"},
                ]
            }
        ]
        result = S3Client.list_objects_recursive("s3://bucket/folder")
        assert result == ["s3://bucket/folder/file1.txt", "s3://bucket/folder/file2.txt"]

    def test_list_objects_recursive_multiple_pages(self, mock_s3_client, mock_paginator):
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "folder/file1.txt"}]},
            {"Contents": [{"Key": "folder/file2.txt"}]},
        ]
        result = S3Client.list_objects_recursive("s3://bucket/folder")
        assert result == ["s3://bucket/folder/file1.txt", "s3://bucket/folder/file2.txt"]

    def test_list_objects_recursive_empty_result(self, mock_s3_client, mock_paginator):
        mock_paginator.paginate.return_value = [{}]
        result = S3Client.list_objects_recursive("s3://bucket/folder")
        assert result == []


class TestReadS3Object:
    def test_read_s3_object_success(self, mock_s3_client, s3_object_body):
        mock_s3_client.get_object.return_value = {"Body": s3_object_body}
        result = S3Client.read_s3_object("s3://bucket/file.txt")
        assert result == "file content"

    def test_read_s3_object_not_found(self, mock_s3_client):
        error_response = {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}
        mock_s3_client.get_object.side_effect = ClientError(error_response, "GetObject")
        with pytest.raises(ClientError) as excinfo:
            S3Client.read_s3_object("s3://bucket/file.txt")
        assert "NoSuchKey" in str(excinfo.value)


class TestChecksumMethods:
    def test_generate_checksum_for_object(self, mock_s3_client):
        mock_s3_client.copy_object.return_value = {
            "CopyObjectResult": {"ChecksumSHA256": "abc123checksum"}
        }
        result = S3Client.generate_checksum_for_object("s3://bucket/file.txt")
        assert result == "abc123checksum"
        mock_s3_client.copy_object.assert_called_once_with(
            Bucket="bucket",
            Key="file.txt",
            CopySource={"Bucket": "bucket", "Key": "file.txt"},
            ChecksumAlgorithm="SHA256",
        )

    def test_generate_checksum_for_object_error(self, mock_s3_client):
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        mock_s3_client.copy_object.side_effect = ClientError(error_response, "CopyObject")
        with pytest.raises(ClientError) as excinfo:
            S3Client.generate_checksum_for_object("s3://bucket/file.txt")
        assert "AccessDenied" in str(excinfo.value)

    def test_get_checksum_for_object_success(self, mock_s3_client):
        mock_s3_client.head_object.return_value = {"ChecksumSHA256": "abc123checksum"}
        result = S3Client.get_checksum_for_object("s3://bucket/file.txt")
        assert result == "abc123checksum"
        mock_s3_client.head_object.assert_called_once_with(
            Bucket="bucket", Key="file.txt", ChecksumMode="ENABLED"
        )

    def test_get_checksum_for_object_no_checksum(self, mock_s3_client):
        mock_s3_client.head_object.return_value = {}  # No checksum in response
        with pytest.raises(ValueError, match="Object does not have a SHA256 checksum"):
            S3Client.get_checksum_for_object("s3://bucket/file.txt")

    def test_calculate_checksum_for_large_object_download_and_hashing_algorithm_success(
        self, tmp_path, mock_s3_client, mocker
    ):
        """This test ensure that the PARALLEL downloading of byte chunks from a file is
        then hashed in an ORDERED fashion to get an accurate SHA256 checksum.

        This is achieved by creating a temporary 10mb file, then mocking the retrieval of
        data chunks to come from this file instead of S3.  The parallel reads and hashing
        are all real, just the origin of the file is mocked.

        The mocked method mock_download_byte_range() introduces some timing randomness
        via a 0-1 second sleep.
        """
        file_size = 10 * 1024 * 1024  # 10mb
        chunk_size = 1 * 1024 * 1024  # 1mb; small, to ensure parallel chunk downloads
        window_size = 5  # small, to ensure parallel chunk downloads

        # create a temporary 10mb file where each 1mb chunk is unique
        filepath = tmp_path / "file.txt"
        file_data = b""
        for x in range(10):
            file_data += (str(x) * chunk_size).encode()
        with open(filepath, "wb") as f:
            f.write(file_data)

        # mock S3 head request file size of 10mb
        mock_s3_client.head_object.return_value = {"ContentLength": file_size}

        def mock_download_byte_range(*args):
            """Mocks downloading byte chunks from S3, coming from local file instead."""
            time.sleep(random.random())  # noqa: S311
            _, _, _, chunk_index, chunk_size = args
            with open(filepath, "rb") as f:
                f.seek(chunk_index * chunk_size)
                return f.read(chunk_size)

        mocker.patch.object(
            S3Client,
            "download_object_byte_range",
            side_effect=mock_download_byte_range,
        )

        # calculate checksum from the full, ordered data
        expected_hash = hashlib.sha256(file_data).digest()
        expected_checksum = base64.b64encode(expected_hash).decode("ascii")

        # get checksum from method and assert the same
        result = S3Client.calculate_checksum_for_large_object(
            "s3://bucket/large_file.txt",
            window_size=window_size,
            chunk_size=chunk_size,
        )
        assert result == expected_checksum
