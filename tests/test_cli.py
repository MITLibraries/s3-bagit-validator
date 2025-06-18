from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pytest
import requests
from click.testing import CliRunner

from lambdas.cli import cli, validate_aip


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
        with patch("lambdas.cli.validate_aip") as mock_validate:
            mock_validate.return_value = {"valid": True, "elapsed": 1.5}

            result = runner.invoke(cli, ["validate", "--aip-uuid", "test-uuid"])
            assert result.exit_code == 0
            assert result.output.strip() == "OK"

    def test_validate_command_with_details(self):
        runner = CliRunner()
        with patch("lambdas.cli.validate_aip") as mock_validate:
            mock_validate.return_value = {"valid": True, "elapsed": 1.5}

            result = runner.invoke(
                cli, ["validate", "--aip-uuid", "test-uuid", "--details"]
            )
            assert result.exit_code == 0
            assert "{'valid': True, 'elapsed': 1.5}" in result.output

    def test_validate_command_failure(self):
        runner = CliRunner()
        with patch("lambdas.cli.validate_aip") as mock_validate:
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
    def test_validate_aip_missing_required_args(self):
        with pytest.raises(
            ValueError, match="Must provide either aip_uuid or aip_s3_uri"
        ):
            validate_aip()
