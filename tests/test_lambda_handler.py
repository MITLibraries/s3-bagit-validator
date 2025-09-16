# ruff: noqa: S105, S106
import json
from http import HTTPStatus
from unittest.mock import patch

import pandas as pd
import pytest

from lambdas import validator
from lambdas.aip import ValidationResponse


class TestInitialization:
    def test_lambda_handler_missing_env_vars_raises_error(self, monkeypatch):
        monkeypatch.delenv("WORKSPACE", raising=False)
        with pytest.raises(
            OSError,
            match="Missing required environment variables: WORKSPACE",
        ):
            validator.lambda_handler({}, {})


class TestInputPayload:
    def test_init_with_valid_data(self):
        payload = validator.InputPayload(
            aip_s3_uri="s3://bucket/aip", challenge_secret="mysecret"
        )
        assert payload.aip_s3_uri == "s3://bucket/aip"
        assert payload.challenge_secret == "mysecret"
        assert payload.action == "validate"
        assert payload.verbose is False
        assert payload.num_workers is None


class TestParsePayload:
    def test_parse_payload_from_http_request(self):
        event = {
            "requestContext": {},
            "body": json.dumps(
                {
                    "aip_s3_uri": "s3://bucket/aip",
                    "challenge_secret": "mysecret",
                    "verbose": True,
                }
            ),
        }

        payload = validator.parse_payload(event)
        assert payload.aip_s3_uri == "s3://bucket/aip"
        assert payload.challenge_secret == "mysecret"
        assert payload.verbose is True
        assert payload.action == "validate"

    def test_parse_payload_from_direct_event(self):
        event = {
            "aip_s3_uri": "s3://bucket/aip",
            "challenge_secret": "mysecret",
            "verbose": False,
        }

        payload = validator.parse_payload(event)
        assert payload.aip_s3_uri == "s3://bucket/aip"
        assert payload.challenge_secret == "mysecret"
        assert payload.verbose is False

    def test_parse_payload_with_aip_uuid(self):
        event = {
            "aip_uuid": "123e4567-e89b-12d3-a456-426614174000",
            "challenge_secret": "mysecret",
        }

        payload = validator.parse_payload(event)
        assert payload.aip_uuid == "123e4567-e89b-12d3-a456-426614174000"
        assert payload.aip_s3_uri is None
        assert payload.challenge_secret == "mysecret"

    def test_parse_payload_with_ping_action(self):
        event = {
            "action": "ping",
            "challenge_secret": "mysecret",
        }

        payload = validator.parse_payload(event)
        assert payload.action == "ping"
        assert payload.aip_s3_uri is None
        assert payload.aip_uuid is None
        assert payload.challenge_secret == "mysecret"

    def test_parse_payload_invalid_raises_value_error(self):
        event = {"msg": "in a bottle"}
        with pytest.raises(ValueError, match="Invalid input payload:"):
            validator.parse_payload(event)


class TestValidateSecret:
    def test_validate_secret_success(self):
        validator.validate_secret("i-am-secret")

    def test_validate_secret_mismatch(self, monkeypatch):
        monkeypatch.setenv("CHALLENGE_SECRET", "i-am-different-secret")
        with pytest.raises(RuntimeError, match="Challenge secret missing or mismatch\\."):
            validator.validate_secret("i-am-secret")


class TestResponseGeneration:
    def test_generate_http_error_response(self):
        response = validator.generate_http_error_response(
            "Test error message", http_status_code=HTTPStatus.BAD_REQUEST
        )
        assert response["statusCode"] == HTTPStatus.BAD_REQUEST
        assert response["headers"] == {"Content-Type": "application/json"}
        assert response["isBase64Encoded"] is False
        assert json.loads(response["body"]) == {
            "error": "Test error message",
            "error_details": None,
        }

    def test_generate_http_error_response_default_status(self):
        response = validator.generate_http_error_response("Test error message")
        assert response["statusCode"] == HTTPStatus.INTERNAL_SERVER_ERROR
        assert json.loads(response["body"]) == {
            "error": "Test error message",
            "error_details": None,
        }

    def test_generate_http_success_response_json_success(self):
        test_data = json.dumps({"key": "value", "nested": {"data": 123}})
        response = validator.generate_http_success_response(
            body=test_data, mimetype="application/json"
        )
        assert response["statusCode"] == HTTPStatus.OK
        assert response["statusDescription"] == "200 OK"
        assert response["headers"] == {"Content-Type": "application/json"}
        assert response["isBase64Encoded"] is False
        assert response["body"] == test_data

    def test_generate_http_success_response_csv_success(self):
        test_data = "123,456,789\nabc,def,ghi"
        response = validator.generate_http_success_response(
            body=test_data, mimetype="text/csv"
        )
        assert response["statusCode"] == HTTPStatus.OK
        assert response["statusDescription"] == "200 OK"
        assert response["headers"] == {"Content-Type": "text/csv"}
        assert response["isBase64Encoded"] is False
        assert response["body"] == test_data


class TestLambdaHandler:
    def test_lambda_handler_success_with_s3_uri(self):
        event = {
            "aip_s3_uri": "s3://bucket/aip",
            "challenge_secret": "i-am-secret",
        }
        mock_result = ValidationResponse(
            bucket="bucket",
            aip_uuid="abc123",
            aip_s3_uri="s3://bucket/aip",
            valid=True,
            elapsed=1.5,
            manifest={"data/file1.txt": "abc123"},
        )
        with patch("lambdas.validator.AIP") as mock_aip_class:
            mock_aip_class.from_s3_uri.return_value = mock_aip_class()
            mock_aip_instance = mock_aip_class.return_value
            mock_aip_instance.validate.return_value = mock_result
            response = validator.lambda_handler(event, {})

        assert response["statusCode"] == HTTPStatus.OK
        assert response["statusDescription"] == "200 OK"
        body = json.loads(response["body"])
        assert body["valid"] is True
        assert body["aip_s3_uri"] == "s3://bucket/aip"

    def test_lambda_handler_success_with_uuid(self):
        event = {
            "aip_uuid": "123e4567-e89b-12d3-a456-426614174000",
            "challenge_secret": "i-am-secret",
        }
        mock_result = ValidationResponse(
            bucket="bucket",
            aip_uuid="abc123",
            aip_s3_uri="s3://bucket/aip",
            valid=True,
            elapsed=1.5,
            manifest={"data/file1.txt": "abc123"},
        )
        with patch("lambdas.validator.AIP") as mock_aip_class:
            mock_aip_class.from_uuid.return_value = mock_aip_class()
            mock_aip_instance = mock_aip_class.return_value
            mock_aip_instance.validate.return_value = mock_result
            response = validator.lambda_handler(event, {})

        assert response["statusCode"] == HTTPStatus.OK
        body = json.loads(response["body"])
        assert body["valid"] is True
        assert body["aip_s3_uri"] == "s3://bucket/aip"

    def test_lambda_handler_inventory_action(self):
        event = {
            "action": "inventory",
            "challenge_secret": "i-am-secret",
        }
        with patch("lambdas.validator.S3InventoryClient") as mock_s3_inventory_client:
            mock_instance = mock_s3_inventory_client.return_value
            mock_instance.get_aips_df.return_value = pd.DataFrame([{"123": "abc"}])
            response = validator.lambda_handler(event, {})

        assert response["statusCode"] == HTTPStatus.OK
        assert response["body"] == "123\nabc\n"

    def test_lambda_handler_ping_action(self):
        event = {
            "action": "ping",
            "challenge_secret": "i-am-secret",
        }
        with patch("lambdas.validator.S3InventoryClient") as mock_s3_inventory_client:
            mock_instance = mock_s3_inventory_client.return_value
            mock_instance.query_inventory.return_value = pd.DataFrame(
                [{"inventory_count": 42}]
            )
            response = validator.lambda_handler(event, {})

        assert response["statusCode"] == HTTPStatus.OK
        body = json.loads(response["body"])
        assert body["response"] == "pong"
        assert "inventory_query_test" in body

    def test_lambda_handler_invalid_payload(self):
        event = {"invalid": "payload"}
        response = validator.lambda_handler(event, {})
        assert response["statusCode"] == HTTPStatus.BAD_REQUEST
        assert "error" in json.loads(response["body"])

    def test_lambda_handler_invalid_secret(self):
        event = {"aip_s3_uri": "s3://bucket/aip", "challenge_secret": "wrong-secret"}
        response = validator.lambda_handler(event, {})
        assert response["statusCode"] == HTTPStatus.UNAUTHORIZED
        assert (
            json.loads(response["body"])["error"]
            == "Challenge secret missing or mismatch."
        )

    def test_lambda_handler_invalid_action(self):
        event = {
            "action": "invalid-action",
            "challenge_secret": "i-am-secret",
        }
        response = validator.lambda_handler(event, {})
        assert response["statusCode"] == HTTPStatus.BAD_REQUEST
        assert "action not recognized" in json.loads(response["body"])["error"]
