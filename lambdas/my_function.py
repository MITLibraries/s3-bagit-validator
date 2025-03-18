import json
import logging
import os

import sentry_sdk
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

env = os.getenv("WORKSPACE")
if sentry_dsn := os.getenv("SENTRY_DSN"):
    sentry = sentry_sdk.init(
        dsn=sentry_dsn,
        environment=env,
        integrations=[
            AwsLambdaIntegration(),
        ],
        traces_sample_rate=1.0,
    )
    logger.info("Sentry DSN found, exceptions will be sent to Sentry with env=%s", env)
else:
    logger.info("No Sentry DSN found, exceptions will not be sent to Sentry")


def lambda_handler(event: dict) -> str:
    if not os.getenv("WORKSPACE"):
        unset_workspace_error_message = "Required env variable WORKSPACE is not set"
        raise RuntimeError(unset_workspace_error_message)

    logger.debug(json.dumps(event))

    return "You have successfully called this lambda!"
