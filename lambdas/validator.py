# ruff: noqa: PLR0911

import json
import logging
from dataclasses import dataclass
from http import HTTPStatus

from lambdas.aip import AIP
from lambdas.config import Config, configure_logger, configure_sentry
from lambdas.exceptions import AIPValidationError
from lambdas.utils.aws import S3InventoryClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CONFIG = Config()


@dataclass
class InputPayload:
    challenge_secret: str
    action: str = "validate"
    aip_s3_uri: str | None = None
    aip_uuid: str | None = None
    verbose: bool = False
    num_workers: int | None = None


def lambda_handler(event: dict, _context: dict) -> dict:
    """AWS Lambda entrypoint.

    This entrypoint handles a direct invocation (e.g. boto3) or an invocation via an HTTP
    request (e.g. ALB or Function URL).  Once the input payload is parsed, and the
    challenge secret verified, the requested 'action' is performed.
    """
    CONFIG.check_required_env_vars()
    configure_sentry()

    # parse payload
    try:
        payload = parse_payload(event)
    except ValueError as exc:
        logger.error(exc)  # noqa: TRY400
        return generate_error_response(str(exc), http_status_code=HTTPStatus.BAD_REQUEST)

    configure_logger(logging.getLogger(), verbose=payload.verbose)
    logger.debug(json.dumps(event))

    # check challenge secret
    try:
        validate_secret(payload.challenge_secret)
    except RuntimeError as exc:
        logger.error(exc)  # noqa: TRY400
        return generate_error_response(str(exc), http_status_code=HTTPStatus.UNAUTHORIZED)

    # perform requested action
    try:
        if payload.action == "ping":
            return ping()
        if payload.action == "inventory":
            return inventory()
        if payload.action == "validate":
            return validate(payload)
        return generate_error_response(
            f"action not recognized: '{payload.action}'",
            http_status_code=HTTPStatus.BAD_REQUEST,
        )
    except AIPValidationError as exc:
        return generate_error_response(
            error=str(exc),
            error_details=exc.error_details,
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    except Exception as exc:
        logger.exception("Unhandled exception")
        return generate_error_response(
            str(exc),
            http_status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        )


def parse_payload(event: dict) -> InputPayload:
    """Parse input payload, raising an exception if invalid.

    This lambda will usually be invoked by an HTTP request to an ALB, resulting in an
    'event' payload as outlined here: https://docs.aws.amazon.com/apigateway/latest/
    developerguide/http-api-develop-integrations-lambda.html.  This function attempts to
    identify what format the event is in before parsing.
    """
    body = json.loads(event["body"]) if "requestContext" in event else event

    try:
        return InputPayload(
            **body,
        )
    except Exception as exc:
        message = f"Invalid input payload: {exc}"
        logger.error(message)  # noqa: TRY400
        raise ValueError(message) from exc


def validate_secret(challenge_secret: str | None) -> None:
    """Check that secret passed with lambda invocation matches secret env var."""
    if not challenge_secret or challenge_secret.strip() != CONFIG.CHALLENGE_SECRET:
        raise RuntimeError("Challenge secret missing or mismatch.")


def generate_error_response(
    error: str,
    error_details: dict | None = None,
    http_status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR,
) -> dict:
    """Produce a response object suitable for HTTP responses.

    See more: https://docs.aws.amazon.com/apigateway/latest/developerguide/
    http-api-develop-integrations-lambda.html
    """
    return {
        "statusCode": http_status_code,
        "headers": {"Content-Type": "application/json"},
        "isBase64Encoded": False,
        "body": json.dumps(
            {
                "error": error,
                "error_details": error_details,
            }
        ),
    }


def generate_result_csv_response(response: str) -> dict:
    """Produce a response object suitable for CSV responses."""
    return {
        "statusCode": HTTPStatus.OK,
        "statusDescription": "200 OK",
        "headers": {"Content-Type": "text/csv"},
        "isBase64Encoded": False,
        "body": response,
    }


def generate_result_http_response(response: dict) -> dict:
    """Produce a response object suitable for HTTP responses.

    See more: https://docs.aws.amazon.com/apigateway/latest/developerguide/
    http-api-develop-integrations-lambda.html
    """
    return {
        "statusCode": HTTPStatus.OK,
        "statusDescription": "200 OK",
        "headers": {"Content-Type": "application/json"},
        "isBase64Encoded": False,
        "body": json.dumps(response),
    }


def ping() -> dict:
    """Return simple 'pong' response."""
    # test Inventory and DuckDB configurations; no exception is a pass
    s3_inventory_client = S3InventoryClient()
    count_df = s3_inventory_client.query_inventory(
        """select count(*) as inventory_count from inventory;"""
    )

    return generate_result_http_response(
        {
            "response": "pong",
            "inventory_query_test": count_df.to_dict(orient="records"),
        }
    )


def inventory() -> dict:
    """Validate a single AIP."""
    s3i_client = S3InventoryClient()
    input_df = s3i_client.get_aips_df()
    csv_string = input_df.to_csv(index=False)
    return generate_result_csv_response(csv_string)


def validate(payload: InputPayload) -> dict:
    """Validate a single AIP."""
    if payload.aip_uuid:
        aip = AIP.from_uuid(payload.aip_uuid)
    elif payload.aip_s3_uri:
        aip = AIP.from_s3_uri(payload.aip_s3_uri)
    else:
        return generate_error_response(
            error="Either AIP S3 URI or UUID is required.",
            http_status_code=HTTPStatus.BAD_REQUEST,
        )

    result = aip.validate(num_workers=payload.num_workers)
    logger.info(f"AIP '{result.aip_s3_uri}' is valid: {result.valid}")

    return generate_result_http_response(result.to_dict(exclude=["manifest"]))
