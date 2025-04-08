import json
import logging
from dataclasses import dataclass
from http import HTTPStatus

from lambdas.aip import AIP
from lambdas.config import Config, configure_logger, configure_sentry
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
        return generate_error_response(str(exc), HTTPStatus.BAD_REQUEST)

    configure_logger(logging.getLogger(), verbose=payload.verbose)
    logger.debug(json.dumps(event))

    # check challenge secret
    try:
        validate_secret(payload.challenge_secret)
    except RuntimeError as exc:
        logger.error(exc)  # noqa: TRY400
        return generate_error_response(str(exc), HTTPStatus.UNAUTHORIZED)

    # perform requested action
    if payload.action == "ping":
        return ping()

    if payload.action == "validate":
        return validate(payload)

    return generate_error_response(
        f"action not recognized: '{payload.action}'",
        HTTPStatus.BAD_REQUEST,
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
        "body": json.dumps({"error": error}),
    }


def generate_result_response(response: dict) -> dict:
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

    return generate_result_response(
        {
            "response": "pong",
            "inventory_query_test": count_df.to_dict(orient="records"),
        }
    )


def validate(payload: InputPayload) -> dict:
    """Validate a single AIP."""
    if payload.aip_uuid and not payload.aip_s3_uri:
        aip = AIP.from_uuid(payload.aip_uuid)
    elif payload.aip_s3_uri:
        aip = AIP.from_s3_uri(payload.aip_s3_uri)
    else:
        raise RuntimeError("Either AIP S3 URI or UUID is required.")

    try:
        result = aip.validate(num_workers=payload.num_workers)
    except Exception as exc:  # noqa: BLE001
        logger.error(exc)  # noqa: TRY400
        return generate_error_response(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    return generate_result_response(result.to_dict())
