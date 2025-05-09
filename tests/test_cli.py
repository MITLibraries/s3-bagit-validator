# ruff: noqa: D205, D209, PLR2004

import json
import shutil
from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
import requests
from click.testing import CliRunner

from lambdas import cli as cli_module
from lambdas.cli import cli, validate_aip_via_lambda


class TestCliCore:
    def test_cli_group_verbose_flag(self):
        runner = CliRunner()
        with patch("lambdas.cli.configure_logger") as mock_config_logger:
            _result = runner.invoke(cli, ["--verbose", "ping"])
            mock_config_logger.assert_called_once()
            assert mock_config_logger.call_args[1]["verbose"] is True


class TestPingCommand:
    def test_ping_success(self):
        runner = CliRunner()
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = HTTPStatus.OK
            mock_response.json.return_value = {"response": "pong"}
            mock_response.text = '{"response": "pong"}'
            mock_post.return_value = mock_response

            result = runner.invoke(cli, ["ping"])
            assert result.exit_code == 0
            assert 'SUCCESS: {"response": "pong"}.' in result.output

    def test_ping_failure(self):
        runner = CliRunner()
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = HTTPStatus.UNAUTHORIZED
            mock_response.json.return_value = {"error": "Invalid challenge secret"}
            mock_response.text = '{"error": "Invalid challenge secret"}'
            mock_post.return_value = mock_response

            result = runner.invoke(cli, ["ping"])
            assert result.exit_code == 1
            assert 'ERROR: {"error": "Invalid challenge secret"}.' in result.output

    def test_ping_connection_timeout(self):
        runner = CliRunner()
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectTimeout(
                "Connection timed out"
            )

            result = runner.invoke(cli, ["ping"])
            assert result.exit_code == 1
            assert "ERROR: timeout connecting" in result.output


class TestValidateCommand:
    def test_validate_command_success(self):
        runner = CliRunner()
        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            mock_validate.return_value = {"valid": True, "elapsed": 1.5}

            result = runner.invoke(cli, ["validate", "--aip-uuid", "test-uuid"])
            assert result.exit_code == 0
            assert result.output.strip() == "OK"

    def test_validate_command_with_details(self):
        runner = CliRunner()
        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            mock_validate.return_value = {"valid": True, "elapsed": 1.5}

            result = runner.invoke(
                cli, ["validate", "--aip-uuid", "test-uuid", "--details"]
            )
            assert result.exit_code == 0
            assert json.loads(result.output) == {"valid": True, "elapsed": 1.5}

    def test_validate_command_failure(self):
        runner = CliRunner()
        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            mock_validate.return_value = {
                "valid": False,
                "error": "Validation failed",
                "error_details": {"problem": "serious"},
            }

            result = runner.invoke(cli, ["validate", "--aip-uuid", "test-uuid"])
            assert result.exit_code == 1
            assert "Validation failed" in result.output

    def test_validate_missing_required_args(self):
        cli_usage_error = 2
        runner = CliRunner()
        result = runner.invoke(cli, ["validate"])
        assert result.exit_code == cli_usage_error
        assert "You must provide either --aip-uuid/-a or --s3-uri/-u" in result.output


class TestBulkValidateCommand:
    def test_bulk_validate_invalid_input_csv(self, tmp_path):
        runner = CliRunner()
        output_path = tmp_path / "output.csv"
        result = runner.invoke(
            cli,
            [
                "bulk-validate",
                "-i",
                "tests/fixtures/cli/bulk-validation/invalid_input.csv",
                "-o",
                output_path,
            ],
        )
        assert result.exit_code == 1
        assert (
            "Input CSV must have 'aip_uuid' and/or 'aip_s3_uri' columns" in result.output
        )

    @pytest.mark.parametrize(
        ("retry_failed", "expected_skipped_count", "expected_skipped_uuids"),
        [
            # With retry flag - all AIPs skipped
            (False, 3, ["test-uuid-1", "test-uuid-2", "test-uuid-3"]),
            # Without retry flag - only previously successful AIPs skipped
            (True, 2, ["test-uuid-2", "test-uuid-3"]),
        ],
    )
    def test_bulk_validate_existing_results(
        self,
        tmp_path,
        retry_failed,
        expected_skipped_count,
        expected_skipped_uuids,
    ):
        """Test bulk validation with existing results, with and without --retry-failed."""
        previous_output_csv = str(tmp_path / "output.csv")
        shutil.copy(
            "tests/fixtures/cli/bulk-validation/existing_results.csv",
            previous_output_csv,
        )

        runner = CliRunner()
        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            # validation results are arbitrary
            mock_validate.side_effect = [
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "aip_uuid": "test-uuid-1",
                    "aip_s3_uri": "s3://bucket/test",
                },
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "aip_uuid": "test-uuid-2",
                    "aip_s3_uri": "s3://bucket/test",
                },
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "aip_uuid": "test-uuid-3",
                    "aip_s3_uri": "s3://bucket/test",
                },
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "aip_uuid": "test-uuid-4",
                    "aip_s3_uri": "s3://bucket/test",
                },
            ]

            args = [
                "--verbose",
                "bulk-validate",
                "-i",
                "tests/fixtures/cli/bulk-validation/existing_results.csv",
                "-o",
                previous_output_csv,
            ]
            if retry_failed:
                args.append("--retry-failed")

            result = runner.invoke(cli, args)

            assert (
                f"Found {expected_skipped_count} already validated AIPs, will skip these."
                in result.output
            )
            for uuid in expected_skipped_uuids:
                assert f"AIP UUID '{uuid}' already validated, skipping." in result.output

    def test_bulk_validate_incremental_writes_during_thread_failures(
        self,
        tmp_path,
    ):
        """Test that even when individual validation threads fail, content is still
        getting written to output CSV."""
        output_csv = str(tmp_path / "output.csv")

        runner = CliRunner()
        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            mock_validate.side_effect = [
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "s3_uri": "s3://bucket/test",
                },
                {
                    "valid": True,
                    "elapsed": 1.5,
                    "s3_uri": "s3://bucket/test",
                },
                SystemExit(),  # mocks an AIP validation thread that quits unexpectedly
                SystemExit(),  # mocks an AIP validation thread that quits unexpectedly
            ]

            args = [
                "--verbose",
                "bulk-validate",
                "-i",
                "tests/fixtures/cli/bulk-validation/input_with_existing_results.csv",
                "-o",
                output_csv,
            ]

            _result = runner.invoke(cli, args)

        # two rows written despite other threads failing
        output_df = pd.read_csv(output_csv)
        assert len(output_df) == 2

    def test_bulk_validate_existing_incrementally_writes_during_parallel_validation(
        self, tmp_path, mocker, reraise
    ):
        """Test that as the threaded worker method validate_aip_bulk_worker runs, rows
        are getting written to the output CSV.  This is important: if the CLI process
        quits unexpectedly, we need to know that each threaded worker had already
        written its content."""
        output_csv = str(tmp_path / "output.csv")

        original_worker = cli_module.validate_aip_bulk_worker

        def wrapper_worker(*args, **kwargs):
            result = original_worker(*args, **kwargs)

            # this use of 'reraise' (from 'pytest-reraise' library) is required for
            # bubbling up assertion failures that occur as part of a multithreaded process
            with reraise:
                _row_index, _row, _results_lock, _results_df, _output_csv_filepath = args
                with _results_lock:
                    output_csv_df = pd.read_csv(_output_csv_filepath)

                    # assert that CSV is growing relative to this AIP getting validated
                    assert len(output_csv_df) == _row_index + 1

                return result

        mocker.patch.object(cli_module, "validate_aip_bulk_worker", wrapper_worker)
        mocker.patch(
            "lambdas.cli.validate_aip_via_lambda",
            return_value={
                "aip_s3_uri": "s3://bucket/test",
                "valid": True,
                "elapsed": 1.5,
            },
        )

        runner = CliRunner()
        args = [
            "--verbose",
            "bulk-validate",
            "-i",
            "tests/fixtures/cli/bulk-validation/input_with_existing_results.csv",
            "-o",
            output_csv,
        ]

        result = runner.invoke(cli, args)
        assert "Validating 4 AIPs" in result.output


class TestInventory:
    def test_inventory_success(self, tmp_path):
        output_csv_filepath = str(tmp_path / "output.csv")
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.content = b"123\nabc\n"
            mock_post.return_value = mock_response
            runner = CliRunner()
            args = [
                "--verbose",
                "inventory",
                "-o",
                output_csv_filepath,
            ]
            result = runner.invoke(cli, args)
            with open(output_csv_filepath) as output_csv:
                assert output_csv.read() == "123\nabc\n"
            assert "AIP inventory CSV created at " in result.output


class TestValidateAipViaLambda:
    def test_validate_aip_via_lambda_with_uuid(self):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"valid": True, "elapsed": 1.5}
            mock_post.return_value = mock_response

            result = validate_aip_via_lambda(aip_uuid="test-uuid")
            assert result == {
                "valid": True,
                "elapsed": 1.5,
            }

            args, kwargs = mock_post.call_args
            assert kwargs["json"]["aip_uuid"] == "test-uuid"
            assert kwargs["json"]["aip_s3_uri"] is None

    def test_validate_aip_via_lambda_with_s3_uri(self):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"valid": True, "elapsed": 1.5}
            mock_post.return_value = mock_response

            result = validate_aip_via_lambda(aip_s3_uri="s3://bucket/aip")
            assert result == {"valid": True, "elapsed": 1.5}

            args, kwargs = mock_post.call_args
            assert kwargs["json"]["aip_s3_uri"] == "s3://bucket/aip"
            assert kwargs["json"]["aip_uuid"] is None

    def test_validate_aip_via_lambda_missing_required_args(self):
        with pytest.raises(
            ValueError, match="Must provide either aip_uuid or aip_s3_uri"
        ):
            validate_aip_via_lambda()
