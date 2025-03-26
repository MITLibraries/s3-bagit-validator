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
        json_result = response.to_json()
        assert isinstance(json_result, str)
        assert (
            json_result
            == '{"s3_uri": "s3://bucket/aip", "valid": true, "elapsed": 1.5, "manifest": null, "error": null}'
        )


class TestAIP:
    def test_init(self):
        aip = AIP("s3://bucket/aip/")
        assert aip.s3_uri == "s3://bucket/aip"
        assert aip.s3_bucket == "bucket"
        assert aip.s3_key == "aip"

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

    def test_decode_base64_sha256(self):
        base64_encoded = "bKE9UspcyIPg8LsQHkJaiebiTeUdstI5JZOvaoQRgJA="
        result = AIP._decode_base64_sha256(base64_encoded)
        assert (
            result == "6ca13d52ca5cc883e0f0bb101e425a89e6e24de51db2d2392593af6a84118090"
        )

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
            assert response.error == "Bagit AIP folder not found in S3: s3://bucket/aip"

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

        with pytest.raises(AIPValidationError) as excinfo:
            aip._check_aip_files_match_manifest()

        assert "Files found in manifest but missing from AIP" in str(excinfo.value)

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

        with pytest.raises(AIPValidationError) as excinfo:
            aip._check_aip_files_match_manifest()

        assert "Files found in AIP but missing from manifest" in str(excinfo.value)

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

        with pytest.raises(AIPValidationError) as excinfo:
            aip._check_checksums()

        assert "Mismatched checksums for files" in str(excinfo.value)
        assert "data/file2.txt" in str(excinfo.value)


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
            )
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
            mocked_inventory.return_value = pd.DataFrame(inventory_data)
            result = aip.validate()

        assert not result.valid
        assert result.error == test_case["expected_error"]
