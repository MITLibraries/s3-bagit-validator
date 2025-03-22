# ruff: noqa: ARG002

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
