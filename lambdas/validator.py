import json
import logging

from lambdas.config import Config, check_verbosity, configure_logger

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

CONFIG = Config()


def lambda_handler(event: dict) -> str:
    """AWS Lambda entrypoint."""
    CONFIG.check_required_env_vars()
    verbose = check_verbosity(event.get("verbose", False))
    configure_logger(logging.getLogger(), verbose=verbose)

    logger.debug(json.dumps(event))

    return "You have successfully called this lambda!"
