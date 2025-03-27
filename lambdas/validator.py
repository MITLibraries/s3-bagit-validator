import json
import logging
from dataclasses import dataclass
from http import HTTPStatus

from lambdas.aip import AIP
from lambdas.config import Config, configure_logger

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CONFIG = Config()


@dataclass
class InputPayload:
    aip_s3_uri: str
    challenge_secret: str
    verbose: bool = False


def lambda_handler(event: dict, _context: dict) -> dict:
    """AWS Lambda entrypoint.

    This entrypoint handles a direct invocation (e.g. boto3) or an invocation via an HTTP
    request (e.g. ALB or Function URL).  Once the input payload is parsed, and the
    challenge secret verified, the AIP class is used to perform validation.
    """
    CONFIG.check_required_env_vars()

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

    # validate AIP
    aip = AIP(payload.aip_s3_uri)
    try:
        result = aip.validate()
    except Exception as exc:  # noqa: BLE001
        logger.error(exc)  # noqa: TRY400
        return generate_error_response(str(exc), HTTPStatus.INTERNAL_SERVER_ERROR)

    return generate_result_response(result.to_dict())


def validate_secret(challenge_secret: str | None) -> None:
    """Check that secret passed with lambda invocation matches secret env var."""
    if not challenge_secret or challenge_secret.strip() != CONFIG.CHALLENGE_SECRET:
        raise RuntimeError("Challenge secret missing or mismatch.")


def parse_payload(event: dict) -> InputPayload:
    """Parse input payload, raising an exception if invalid.

    This lambda will usually be invoked by an HTTP request to an ALB, resulting in an
    'event' payload as outlined here: https://docs.aws.amazon.com/apigateway/latest/
    developerguide/http-api-develop-integrations-lambda.html.  This function attempts to
    identify what format the event is in before parsing.
    """
    body = json.loads(event["body"]) if "requestContext" in event else event

    try:
        return InputPayload(**body)
    except Exception as exc:
        message = f"Invalid input payload: {exc}"
        logger.error(message)  # noqa: TRY400
        raise ValueError(message) from exc


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
