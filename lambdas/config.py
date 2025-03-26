import logging
import os
from typing import Any

import sentry_sdk
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Config:
    REQUIRED_ENV_VARS = (
        "WORKSPACE",
        "SENTRY_DSN",
        "AWS_ATHENA_WORK_GROUP",
        "AWS_ATHENA_DATABASE",
    )
    OPTIONAL_ENV_VARS = (
        "AWS_DEFAULT_REGION",
        "WARNING_ONLY_LOGGERS",
        "INTEGRATION_TEST_BUCKET",
        "INTEGRATION_TEST_PREFIX",
    )

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        """Provide dot notation access to configurations and env vars on this class."""
        if name in self.REQUIRED_ENV_VARS or name in self.OPTIONAL_ENV_VARS:
            return os.getenv(name)
        message = f"'{name}' not a valid configuration variable"
        raise AttributeError(message)

    def check_required_env_vars(self) -> None:
        """Method to raise exception if required env vars not set."""
        missing_vars = [var for var in self.REQUIRED_ENV_VARS if not os.getenv(var)]
        if missing_vars:
            message = f"Missing required environment variables: {', '.join(missing_vars)}"
            raise OSError(message)

    @property
    def aws_region(self) -> str:
        return self.AWS_DEFAULT_REGION or "us-east-1"


def check_verbosity(verbose: bool | str) -> bool:
    """Determine whether verbose is True or False given a boolean or string value."""
    if isinstance(verbose, bool):
        return verbose
    return verbose.lower() == "true"


def configure_logger(
    root_logger: logging.Logger,
    *,
    verbose: bool = False,
    warning_only_loggers: str | None = None,
) -> str:
    """Configure application via passed application root logger.

    If verbose=True, 3rd party libraries can be quite chatty.  For convenience, they can
    be set to WARNING level by either passing a comma seperated list of logger names to
    'warning_only_loggers' or by setting the env var WARNING_ONLY_LOGGERS.
    """
    if verbose:
        root_logger.setLevel(logging.DEBUG)
        logging_format = (
            "%(asctime)s %(levelname)s %(name)s.%(funcName)s() "
            "line %(lineno)d: %(message)s"
        )
    else:
        root_logger.setLevel(logging.INFO)
        logging_format = "%(asctime)s %(levelname)s %(name)s.%(funcName)s(): %(message)s"

    warning_only_loggers = os.getenv("WARNING_ONLY_LOGGERS", warning_only_loggers)
    if warning_only_loggers:
        for name in warning_only_loggers.split(","):
            logging.getLogger(name).setLevel(logging.WARNING)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(logging_format))
    root_logger.addHandler(handler)

    return (
        f"Logger '{root_logger.name}' configured with level="
        f"{logging.getLevelName(root_logger.getEffectiveLevel())}"
    )


def configure_sentry() -> None:
    CONFIG = Config()  # noqa: N806
    env = CONFIG.WORKSPACE
    if sentry_dsn := CONFIG.SENTRY_DSN:
        sentry_sdk.init(
            dsn=sentry_dsn,
            environment=env,
            integrations=[
                AwsLambdaIntegration(),
            ],
            traces_sample_rate=1.0,
        )
        logger.info(
            "Sentry DSN found, exceptions will be sent to Sentry with env=%s", env
        )
    else:
        logger.info("No Sentry DSN found, exceptions will not be sent to Sentry")
