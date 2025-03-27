# ruff: noqa: S105, S106
import json
from http import HTTPStatus
from unittest.mock import patch

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
        assert payload.verbose is False

    def test_init_with_verbose_true(self):
        payload = validator.InputPayload(
            aip_s3_uri="s3://bucket/aip", challenge_secret="mysecret", verbose=True
        )
        assert payload.verbose is True


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

    def test_parse_payload_invalid_raises_value_error(self):
        event = {"body": json.dumps({"wrong_param": "value"})}
        with pytest.raises(ValueError, match="Invalid input payload:"):
            validator.parse_payload(event)


class TestValidateSecret:
    def test_validate_secret_success(self):
        validator.validate_secret("i-am-secret")

    def test_validate_secret_mismatch(self, monkeypatch):
        monkeypatch.setenv("CHALLENGE_SECRET", "i-am-different-secret")
        with pytest.raises(RuntimeError, match="Challenge secret missing or mismatch."):
            validator.validate_secret("i-am-secret")


class TestResponseGeneration:
    def test_generate_error_response(self):
        response = validator.generate_error_response(
            "Test error message", HTTPStatus.BAD_REQUEST
        )
        assert response["statusCode"] == HTTPStatus.BAD_REQUEST
        assert response["headers"] == {"Content-Type": "application/json"}
        assert response["isBase64Encoded"] is False
        assert json.loads(response["body"]) == {"error": "Test error message"}

    def test_generate_error_response_default_status(self):
        response = validator.generate_error_response("Test error message")
        assert response["statusCode"] == HTTPStatus.INTERNAL_SERVER_ERROR
        assert json.loads(response["body"]) == {"error": "Test error message"}

    def test_generate_result_response(self):
        test_data = {"key": "value", "nested": {"data": 123}}
        response = validator.generate_result_response(test_data)
        assert response["statusCode"] == HTTPStatus.OK
        assert response["statusDescription"] == "200 OK"
        assert response["headers"] == {"Content-Type": "application/json"}
        assert response["isBase64Encoded"] is False
        assert json.loads(response["body"]) == test_data


class TestLambdaHandler:
    def test_lambda_handler_success(self):
        event = {
            "aip_s3_uri": "s3://bucket/aip",
            "challenge_secret": "i-am-secret",
        }
        mock_result = ValidationResponse(
            s3_uri="s3://bucket/aip",
            valid=True,
            elapsed=1.5,
            manifest={"data/file1.txt": "abc123"},
        )
        with patch("lambdas.validator.AIP") as mock_aip_class:
            mock_aip_instance = mock_aip_class.return_value
            mock_aip_instance.validate.return_value = mock_result
            response = validator.lambda_handler(event, {})

        assert response["statusCode"] == HTTPStatus.OK
        assert response["statusDescription"] == "200 OK"
        body = json.loads(response["body"])
        assert body["valid"] is True
        assert body["s3_uri"] == "s3://bucket/aip"
        assert body["manifest"] == {"data/file1.txt": "abc123"}

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
