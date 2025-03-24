import logging
import time
from typing import TYPE_CHECKING, Optional

import pandas as pd
from sqlalchemy.engine import create_engine

from lambdas.config import Config

CONFIG = Config()

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


class AthenaClient:

    def __init__(
        self,
        database: str | None = None,
        engine: Optional["Engine"] = None,
    ):
        self.database = database
        if not engine:
            self.engine = self.get_athena_sqlalchemy_engine(self.database)

    @classmethod
    def get_athena_sqlalchemy_engine(cls, database: str | None = None) -> "Engine":
        """Provide a SQLAlchemy engine with a PyAthena driver connection."""
        if not database:
            database = CONFIG.AWS_ATHENA_DATABASE
        connection_string = (
            f"awsathena://:@athena.{CONFIG.aws_region}.amazonaws.com:443/{database}"
        )
        engine = create_engine(connection_string)
        logger.debug(f"SQLAlchemy engine created: {engine}")
        return engine

    def query(self, query_string: str) -> pd.DataFrame:
        """Perform an Athena query."""
        t0 = time.time()
        with self.engine.connect() as conn:
            results_df = pd.read_sql_query(query_string, conn)
            logger.debug(f"Athena query elapsed: {time.time() - t0}")
            return results_df
