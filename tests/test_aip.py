# ruff: noqa: PLR2004, SLF001, PD901, SIM117, ARG002, E501

import os
from unittest.mock import patch

import boto3
import pandas as pd
import pytest

from lambdas.aip import AIP, ValidationResponse
from lambdas.exceptions import AIPValidationError


class TestValidationResponse:
    def test_to_dict(self):
        response = ValidationResponse(
            s3_uri="s3://bucket/aip",
            valid=True,
            elapsed=1.5,
            manifest={"data/file1.txt": "abc123"},
            error=None,
        )
        result = response.to_dict()

        assert isinstance(result, dict)
        assert result["s3_uri"] == "s3://bucket/aip"
        assert result["valid"] is True
        assert result["elapsed"] == 1.5
        assert result["manifest"] == {"data/file1.txt": "abc123"}
        assert result["error"] is None

    def test_to_dict_with_error(self):
        response = ValidationResponse(
            s3_uri="s3://bucket/aip", valid=False, elapsed=1.5, error="Validation failed"
        )
        result = response.to_dict()
        assert result["valid"] is False
        assert result["error"] == "Validation failed"
        assert result["manifest"] is None

    def test_to_json(self):
        response = ValidationResponse(s3_uri="s3://bucket/aip", valid=True, elapsed=1.5)
        json_result = response.to_json(exclude=["manifest", "error", "error_details"])
        assert isinstance(json_result, str)
        assert (
            json_result == '{"s3_uri": "s3://bucket/aip", "valid": true, "elapsed": 1.5}'
        )


class TestAIP:
    def test_init(self):
        aip = AIP("s3://bucket/aip/")
        assert aip.s3_uri == "s3://bucket/aip"
        assert aip.s3_bucket == "bucket"
        assert aip.s3_key == "aip"

    def test_init_from_uuid_success(self):
        """Test successful initialization from a valid UUID."""
        with patch(
            "lambdas.utils.aws.S3InventoryClient.get_aip_from_uuid"
        ) as mock_get_aip:
            mock_aip_series = pd.Series(
                {
                    "aip_s3_uri": "s3://bucket/path/to/aip",
                    "aip_s3_key": "path/to/aip",
                    "bucket": "bucket",
                }
            )
            mock_get_aip.return_value = mock_aip_series
            aip = AIP.from_uuid("valid-uuid-12345")

            mock_get_aip.assert_called_once_with("valid-uuid-12345")
            assert aip.s3_uri == "s3://bucket/path/to/aip"
            assert aip.s3_bucket == "bucket"
            assert aip.s3_key == "path/to/aip"

    def test_init_from_uuid_none_found(self):
        """Test that ValueError is bubbled up when UUID is not found."""
        with patch(
            "lambdas.utils.aws.S3InventoryClient.get_aip_from_uuid"
        ) as mock_get_aip:
            mock_get_aip.side_effect = ValueError("AIP UUID 'missing-uuid' not found")

            with pytest.raises(ValueError, match="AIP UUID 'missing-uuid' not found"):
                AIP.from_uuid("missing-uuid")

    def test_init_from_uuid_multiple_found(self):
        """Test that TypeError is bubbled up when multiple AIPs with same UUID exist."""
        with patch(
            "lambdas.utils.aws.S3InventoryClient.get_aip_from_uuid"
        ) as mock_get_aip:
            mock_get_aip.side_effect = TypeError(
                "Multiple entries found for AIP UUID 'duplicate-uuid'"
            )

            with pytest.raises(
                TypeError, match="Multiple entries found for AIP UUID 'duplicate-uuid'"
            ):
                AIP.from_uuid("duplicate-uuid")

    def test_data_files_property(self):
        aip = AIP("s3://bucket/aip")
        aip.files = [
            "bagit.txt",
            "manifest-sha256.txt",
            "data/file1.txt",
            "data/file2.txt",
        ]
        assert aip.data_files == ["data/file1.txt", "data/file2.txt"]

    def test_manifest_as_dict_property(self):
        aip = AIP("s3://bucket/aip")
        aip.manifest_df = pd.DataFrame(
            [
                {"filepath": "data/file1.txt", "checksum": "abc123"},
                {"filepath": "data/file2.txt", "checksum": "def456"},
            ]
        )
        assert aip.manifest_as_dict == {
            "data/file1.txt": "abc123",
            "data/file2.txt": "def456",
        }

    def test_validate_success(
        self,
        mock_aip_folder,
        mock_manifest_data,
        mock_aip_files,
        mock_inventory_data,
        mock_checksums,
    ):

        aip = AIP("s3://bucket/aip")
        response = aip.validate()

        assert response.valid is True
        assert response.s3_uri == "s3://bucket/aip"
        assert response.error is None

    def test_validate_folder_not_exists(self):

        with patch("lambdas.utils.aws.s3.S3Client.folder_exists") as mock_folder_exists:
            mock_folder_exists.return_value = False

            aip = AIP("s3://bucket/aip")
            response = aip.validate()

            assert response.valid is False
            assert response.error == "Bagit AIP folder not found in S3"
            assert response.error_details == {
                "type": "aip_folder_not_found",
                "s3_uri": "s3://bucket/aip",
            }

    def test_check_aip_files_match_manifest_missing_files(
        self, mock_aip_folder, mock_manifest_data
    ):
        aip = AIP("s3://bucket/aip")
        aip.manifest_df = pd.DataFrame(
            [
                {"filepath": "data/file1.txt", "checksum": "abc"},
                {"filepath": "data/file2.txt", "checksum": "def"},
                {
                    "filepath": "data/file3.txt",  # Extra file in manifest
                    "checksum": "ghi",
                },
            ]
        )
        aip.files = [
            "bagit.txt",
            "manifest-sha256.txt",
            "data/file1.txt",
            "data/file2.txt",
        ]

        with pytest.raises(AIPValidationError) as exc:
            aip._check_aip_files_match_manifest()

        assert "Files found in manifest but missing from AIP" in str(exc.value)

    def test_check_aip_files_match_manifest_extra_files(
        self, mock_aip_folder, mock_manifest_data
    ):
        aip = AIP("s3://bucket/aip")
        aip.manifest_df = pd.DataFrame(
            [{"filepath": "data/file1.txt", "checksum": "abc"}]
        )
        aip.files = [
            "bagit.txt",
            "manifest-sha256.txt",
            "data/file1.txt",
            "data/file2.txt",
        ]

        with pytest.raises(AIPValidationError) as exc:
            aip._check_aip_files_match_manifest()

        assert "Files found in AIP but missing from manifest" in str(exc.value)

    def test_check_checksums_mismatch(self):
        aip = AIP("s3://bucket/aip")
        aip.manifest_df = pd.DataFrame(
            [
                {"filepath": "data/file1.txt", "checksum": "abc123"},
                {"filepath": "data/file2.txt", "checksum": "def456"},
            ]
        )
        aip.file_checksums = {
            "data/file1.txt": "abc123",  # Matches
            "data/file2.txt": "wrong",  # Doesn't match
        }

        with pytest.raises(AIPValidationError) as exc:
            aip._check_checksums()

        assert "Mismatched checksums for files" in str(exc.value)
        assert "data/file2.txt" in exc.value.error_details["mismatched_files"]

    def test_check_checksums_mismatch_truncation(self):
        aip = AIP("s3://bucket/aip")

        # create mismatched files exceeding the file limit
        file_count = 150
        manifest_data = []
        file_checksums = {}
        for i in range(file_count):
            filepath = f"data/file{i}.txt"
            manifest_data.append({"filepath": filepath, "checksum": f"expected{i}"})
            file_checksums[filepath] = f"actual{i}"

        # mock manifest data and checksums to provoke checksum mismatches
        aip.manifest_df = pd.DataFrame(manifest_data)
        aip.file_checksums = file_checksums
        with pytest.raises(AIPValidationError) as exc:
            aip._check_checksums()

        # check that error details are truncated
        assert "warning" in exc.value.error_details["manifest_checksums"]
        assert (
            exc.value.error_details["manifest_checksums"]["warning"]
            == "too many individual files to list"
        )
        assert "warning" in exc.value.error_details["s3_checksums"]
        assert (
            exc.value.error_details["s3_checksums"]["warning"]
            == "too many individual files to list"
        )

    def test_get_aip_file_checksums(self):
        """Test that _get_aip_file_checksums correctly processes files in parallel."""
        aip = AIP("s3://bucket/aip")

        aip.manifest_df = pd.DataFrame(
            [
                {"filepath": "data/file1.txt", "checksum": "abc123"},
                {"filepath": "data/file2.txt", "checksum": "def456"},
                {"filepath": "data/file3.txt", "checksum": "ghi789"},
            ]
        )

        one_mb_size = 1 * 1024 * 1024
        aip.s3_inventory = pd.DataFrame(
            [
                {
                    "key": "aip/data/file1.txt",
                    "checksum_algorithm": "SHA256",
                    "size": one_mb_size,
                    "is_multipart_uploaded": False,
                },
                {
                    "key": "aip/data/file2.txt",
                    "checksum_algorithm": "SHA256",
                    "size": one_mb_size,
                    "is_multipart_uploaded": False,
                },
                {
                    "key": "aip/data/file3.txt",
                    "checksum_algorithm": "MD5",
                    "size": one_mb_size,
                    "is_multipart_uploaded": False,
                },
            ]
        ).set_index("key")

        # Mock the S3Client methods
        with patch("lambdas.utils.aws.s3.S3Client.get_checksum_for_object") as mock_get:
            with patch(
                "lambdas.utils.aws.s3.S3Client.generate_checksum_for_object"
            ) as mock_generate:
                with patch(
                    "lambdas.utils.aws.s3.S3Client._decode_base64_sha256"
                ) as mock_decode:
                    mock_get.side_effect = lambda _: "base64_checksum"
                    mock_generate.side_effect = lambda _: "base64_checksum"
                    mock_decode.return_value = "expected_checksum_xxxyyy111222"

                    file_checksums = aip._get_aip_file_checksums(num_workers=2)

        assert len(file_checksums) == 3
        assert set(file_checksums.keys()) == {
            "data/file1.txt",
            "data/file2.txt",
            "data/file3.txt",
        }
        for value in file_checksums.values():
            assert value == "expected_checksum_xxxyyy111222"

        assert mock_get.call_count == 2  # called for two existing SHA256 checksums
        assert mock_generate.call_count == 1  # called for single MD5 checksum
        assert mock_decode.call_count == 3


@pytest.mark.integration
class TestAIPIntegration:
    """Integration tests for the AIP class that validate S3 operations."""

    @pytest.fixture
    def s3_integration_client(self):
        return boto3.client("s3")

    @pytest.fixture
    def integration_bucket(self, request):
        """Fixture that returns the integration test bucket name."""
        marker = request.node.get_closest_marker("integration")
        if not marker:
            pytest.skip("Only for integration tests")
        return os.environ["INTEGRATION_TEST_BUCKET"]

    @pytest.fixture
    def integration_prefix(self, request):
        """Fixture that returns the integration test prefix."""
        marker = request.node.get_closest_marker("integration")
        if not marker:
            pytest.skip("Only for integration tests")
        return os.environ["INTEGRATION_TEST_PREFIX"]

    @pytest.fixture
    def setup_s3_aip(self, s3_integration_client, integration_bucket, integration_prefix):
        """Fixture that uploads a test AIP to S3."""
        uploaded_aips = []

        def _upload_aip(local_aip_directory):
            bucket = integration_bucket
            aip_name = local_aip_directory.split("/")[-1]
            key = f"{integration_prefix}/{aip_name}"
            uri = f"s3://{bucket}/{key}"

            local_aip_directory = local_aip_directory.removesuffix("/") + "/"
            for root, _exit, files in os.walk(local_aip_directory):
                for filename in files:
                    local_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(local_path, local_aip_directory)
                    s3_key = os.path.join(key, relative_path)
                    s3_integration_client.upload_file(local_path, bucket, s3_key)

            uploaded_aips.append(uri)
            return uri

        return _upload_aip

    def test_aip_validate_success(self, setup_s3_aip, integration_prefix):
        """Test successful validation of a valid AIP."""
        s3_uri = setup_s3_aip("tests/fixtures/aips/valid-aip")
        aip = AIP(s3_uri)

        # mock S3 inventory data as we don't have this for ad-hoc uploaded AIPs
        with patch.object(aip, "_get_aip_s3_inventory") as mocked_inventory:
            mocked_inventory.return_value = pd.DataFrame(
                [
                    {
                        "key": f"{integration_prefix}/valid-aip/data/hello.txt",
                        "checksum_algorithm": "NotHelpful",
                    }
                ]
            ).set_index("key")
            result = aip.validate()

        # Assertions
        assert result.valid
        assert result.s3_uri == s3_uri
        assert result.error is None

    def test_aip_fails_validate_inventory_data_not_found(
        self, setup_s3_aip, integration_prefix
    ):
        """Test validation failure when inventory data is missing."""
        s3_uri = setup_s3_aip("tests/fixtures/aips/valid-aip")
        aip = AIP(s3_uri)

        # no mocking required, fails naturally because no S3 inventory for ad-hoc upload
        result = aip.validate()

        assert not result.valid
        assert (
            f"S3 Inventory data not found for S3 key: '{integration_prefix}/valid-aip'"
            in result.error
        )
        assert result.error_details == {
            "type": "s3_inventory_not_found",
            "s3_key": f"{integration_prefix}/valid-aip",
        }

    @pytest.mark.parametrize(
        "test_case",
        [
            {
                "fixture_path": "tests/fixtures/aips/missing-file-in-aip",
                "inventory_data": [
                    # Note: file1.txt not in S3 AIP, so not in inventory
                    {
                        "key_suffix": "data/file2.txt",
                        "checksum_algorithm": "NotHelpful",
                    }
                ],
                "expected_error": 'Files found in manifest but missing from AIP: ["data/file1.txt"]',
                "expected_error_details": {
                    "type": "files_missing_in_aip",
                    "missing_files": ["data/file1.txt"],
                },
            },
            {
                "fixture_path": "tests/fixtures/aips/missing-file-in-manifest",
                "inventory_data": [
                    {
                        "key_suffix": "data/file1.txt",
                        "checksum_algorithm": "NotHelpful",
                    },
                    {
                        "key_suffix": "data/file2.txt",
                        "checksum_algorithm": "NotHelpful",
                    },
                ],
                "expected_error": 'Files found in AIP but missing from manifest: ["data/file1.txt"]',
                "expected_error_details": {
                    "type": "files_missing_in_manifest",
                    "missing_files": ["data/file1.txt"],
                },
            },
            {
                "fixture_path": "tests/fixtures/aips/checksum-mismatch",
                "inventory_data": [
                    {
                        "key_suffix": "data/file1.txt",
                        "checksum_algorithm": "NotHelpful",
                    }
                ],
                "expected_error": 'Mismatched checksums for files: ["data/file1.txt"]',
                "expected_error_details": {
                    "type": "checksum_mismatch",
                    "mismatched_files": ["data/file1.txt"],
                    "manifest_checksums": {
                        "data/file1.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    },
                    "s3_checksums": {"data/file1.txt": "different_checksum"},
                },
            },
        ],
        ids=["missing-file-in-aip", "missing-file-in-manifest", "checksum-mismatch"],
    )
    def test_aip_validation_failures(self, setup_s3_aip, integration_prefix, test_case):
        """Parameterized test for various validation failure scenarios."""
        fixture_path = test_case["fixture_path"]
        aip_name = fixture_path.split("/")[-1]

        s3_uri = setup_s3_aip(fixture_path)
        aip = AIP(s3_uri)

        inventory_data = []
        for item in test_case["inventory_data"]:
            inventory_data.append(  # noqa: PERF401
                {
                    "key": f"{integration_prefix}/{aip_name}/{item['key_suffix']}",
                    "checksum_algorithm": item["checksum_algorithm"],
                }
            )

        with patch.object(aip, "_get_aip_s3_inventory") as mocked_inventory:
            mocked_inventory.return_value = pd.DataFrame(inventory_data).set_index("key")

            # for checksum mismatch test, we need to mock the checksums
            if "checksum-mismatch" in fixture_path:
                with patch.object(aip, "_get_aip_file_checksums") as mock_checksums:
                    mock_checksums.return_value = {"data/file1.txt": "different_checksum"}
                    result = aip.validate()
            else:
                result = aip.validate()

        assert not result.valid
        assert result.error == test_case["expected_error"]

        # check that error_details has the expected structure
        expected_error_details = test_case["expected_error_details"]
        assert result.error_details["type"] == expected_error_details["type"]

        # check specific fields based on error type
        if (
            expected_error_details["type"] == "files_missing_in_aip"
            or expected_error_details["type"] == "files_missing_in_manifest"
        ):
            assert set(result.error_details["missing_files"]) == set(
                expected_error_details["missing_files"]
            )
        elif expected_error_details["type"] == "checksum_mismatch":
            assert set(result.error_details["mismatched_files"]) == set(
                expected_error_details["mismatched_files"]
            )
            assert "manifest_checksums" in result.error_details
            assert "s3_checksums" in result.error_details
