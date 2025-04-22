import json
from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
import requests
from click.testing import CliRunner

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
    def test_bulk_validate_success(self, tmp_path):
        runner = CliRunner()
        output_path = tmp_path / "output.csv"

        with patch("lambdas.cli.validate_aip_via_lambda") as mock_validate:
            mock_validate.return_value = {
                "valid": True,
                "elapsed": 1.5,
                "s3_uri": "s3://bucket/test",
            }

            result = runner.invoke(
                cli,
                [
                    "bulk-validate",
                    "-i",
                    "tests/fixtures/cli/bulk-validation/single_uuid_input.csv",
                    "-o",
                    str(output_path),
                ],
            )
            assert result.exit_code == 0
            assert f"Results saved to {output_path}" in result.output

            output_data = pd.read_csv(output_path)
            assert len(output_data) == 1
            assert bool(output_data["valid"].iloc[0]) is True

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
