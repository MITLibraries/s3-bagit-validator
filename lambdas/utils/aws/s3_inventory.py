# ruff: noqa: S608

import concurrent.futures
import datetime
import logging
import re
import time

import duckdb
import pandas as pd

from lambdas.config import Config
from lambdas.utils.aws import S3Client

logger = logging.getLogger(__name__)

CONFIG = Config()


class S3InventoryClient:
    """Client to query S3 Inventory data for a one or more S3 Inventory outputs.

    S3 Inventory data is stored in S3 according to this specification:
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory-location.html

    AWS Athena was originally used for S3 Inventory queries, but it was found to not scale
    well horizontally for lots of small, concurrent requests.  This client sidesteps that
    limitation by identifying the most recent parquet files for each Inventory configured
    and then using DuckDB to query those parquet files directly.
    """

    def __init__(self, inventory_uris: list[str] | None = None) -> None:
        self.s3_client = S3Client()
        self.inventory_uris = inventory_uris or CONFIG.aip_s3_inventory_uris

        # caches
        self._inventory_parquet_files: list[str] | None = None
        self._aips_df: pd.DataFrame | None = None
        self._aip_inventories: dict = {}

    @staticmethod
    def extract_dt_date_from_s3_key(s3_uri: str) -> datetime.datetime:
        if match := re.search(r"dt=([^/]+)", s3_uri):
            date_string = match.group(1)
        else:
            raise ValueError(f"Could not parse datetime partition from uri: {s3_uri}")
        return datetime.datetime.strptime(date_string, "%Y-%m-%d-%H-%M")  # noqa: DTZ007

    def get_single_inventory_parquet_files(self, inventory_uri: str) -> list[str]:
        """Retrieve most recent parquet files for an Inventory location.

        List all objects recursively for the Inventory location, filter down to only
        'symlink.txt' objects, then sort them by a datetime embedded in the key.  Lastly,
        read the symlink.txt for an explicit list of parquet file S3 URIs that fulfill
        that Inventory data.

        Args:
            inventory_uri: S3 URI of the root of the S3 Inventory data
        """
        objects = list(self.s3_client.list_objects_recursive(inventory_uri))
        objects = [obj for obj in objects if obj.endswith("symlink.txt")]
        objects.sort(
            key=self.extract_dt_date_from_s3_key,
            reverse=True,
        )
        target_key = objects[0]
        symlink_data = self.s3_client.read_s3_object(target_key)
        return [x.strip() for x in symlink_data.split("\n")]

    def get_all_inventory_parquet_files(self) -> list[str]:
        """Get most recent parquet file URIs for all configured S3 Inventories.

        Parquet files are discovered for each configured Inventory location in parallel
        via threads.  In case of client reuse, these identified parquet files are cached.
        """
        if self._inventory_parquet_files:
            return self._inventory_parquet_files
        start_time = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # submit parallel tasks
            inventory_futures = {
                executor.submit(self.get_single_inventory_parquet_files, bucket): bucket
                for bucket in self.inventory_uris
            }

            # wait for tasks to complete
            inventory_parquet_files = []
            for future in concurrent.futures.as_completed(inventory_futures):
                try:
                    parquet_files = future.result()
                    inventory_parquet_files.extend(parquet_files)
                except Exception as exc:
                    inventory = inventory_futures[future]
                    raise RuntimeError(
                        f"Error processing inventory: {inventory}: {exc}"
                    ) from exc

        if not inventory_parquet_files:
            raise RuntimeError(
                "Could not find any parquet files for configured Inventories."
            )

        logger.debug(f"Inventory parquet files found: {time.perf_counter()-start_time}")
        self._inventory_parquet_files = inventory_parquet_files
        return inventory_parquet_files

    def query_inventory(
        self,
        query: str,
        params: dict | list | None = None,
    ) -> pd.DataFrame:
        """Perform SQL query against Inventory parquet files via DuckDB."""
        start_time = time.perf_counter()
        with duckdb.connect() as conn:
            self._duckdb_set_aws_credentials(conn)
            self._duckdb_create_inventory_view(conn)
            results_df = conn.query(query, params=params).to_df()
            logger.debug(f"Inventory query elapsed: {time.perf_counter() - start_time}")
            return results_df

    def _duckdb_set_aws_credentials(self, conn: duckdb.DuckDBPyConnection) -> None:
        """Create AWS credentials secret to handle env or SSO credentials chain."""
        conn.execute(
            """
        CREATE OR REPLACE SECRET aws_secret (
            TYPE s3,
            PROVIDER credential_chain,
            CHAIN 'env;sso;process'
        );
        """
        )

    def _duckdb_create_inventory_view(self, conn: duckdb.DuckDBPyConnection) -> None:
        """Create DuckDB view from all identified Inventory parquet files."""
        parquet_files = self.get_all_inventory_parquet_files()
        conn.execute(
            f"""
                    create view inventory as (
                        select
                            *,
                            filename
                        from read_parquet(
                            {parquet_files},
                            filename=true
                        )
                    );
                    """
        )

    def get_aips_df(self) -> pd.DataFrame:
        """Get DataFrame of all AIPs in S3 Inventory.

        This data is particularly helpful for mapping an AIP UUID to the precise S3 URI
        for that AIP.

        The dataframe includes information such as:
            - AIP UUID
            - full S3 URI of AIP
            - AIP file count
            - size of AIP
            - min / max dates of modified files in AIP
        """
        if self._aips_df is not None:
            return self._aips_df

        # ruff: noqa: E501
        query = """
        with cdps_aip_inventory as (
            select * from inventory
            where is_latest
            and not is_delete_marker
        ),
        cdps_aip_inventory_with_aip_uuid as (
            select
                bucket,
                -- extract the *first* UUID encountered in the key
                case
                    when key ~ '.+?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*'
                    then regexp_extract(key, '.+?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*', 1)
                    else null
                end as aip_uuid,
                -- extract the inventory root as they key up until, and inclusive, of the first UUID
                case
                    when key ~ '.+?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*'
                    then regexp_extract(key, '(.+?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).*', 1)
                    else null
                end as aip_s3_key,
                key,
                size,
                last_modified_date
            from cdps_aip_inventory
        )
        select
            bucket,
            aip_uuid,
            aip_s3_key,
            concat('s3://', bucket, '/', aip_s3_key) as aip_s3_uri,
            count(*) as aip_files_count,
            sum(size) as total_size_bytes,
            min(last_modified_date) as earliest_file_date,
            max(last_modified_date) as latest_file_date
        from cdps_aip_inventory_with_aip_uuid
        where aip_uuid is not null
        group by bucket, aip_uuid, aip_s3_key, aip_s3_uri
        order by aip_files_count desc;
        """
        # ruff: enable: E501

        aips_df = self.query_inventory(query)

        # integrity checks
        if len(aips_df) == 0:
            raise RuntimeError("No AIPs found in inventory data.")

        self._aips_df = aips_df
        return aips_df

    def get_aip_from_uuid(self, aip_uuid: str) -> pd.Series:
        """Retrieve information about a specific AIP by its UUID."""
        aips_df = self.get_aips_df()

        if aip_uuid not in aips_df["aip_uuid"].to_numpy():
            raise ValueError(f"AIP UUID '{aip_uuid}' not found")
        aip = aips_df.set_index("aip_uuid").loc[aip_uuid]
        if isinstance(aip, pd.DataFrame):
            raise TypeError(f"Multiple entries found for AIP UUID '{aip_uuid}'")

        return aip

    def get_aip_inventory(
        self,
        *,
        aip_uuid: str | None = None,
        aip_s3_key: str | None = None,
    ) -> pd.DataFrame:
        """Retrieve S3 Inventory data for a single AIP by UUID or S3 key prefix.

        Args:
            aip_uuid: str, AIP UUID
            aip_s3_key: str, key prefix for AIP
                e.g. 5b33/1bf3/eb1f/4017/bbe8/c24a/9f60/f4cd/
                2014_039_002-5b331bf3-eb1f-4017-bbe8-c24a9f60f4cd
        """
        if not aip_uuid and not aip_s3_key:
            raise ValueError("Either 'aip_uuid' or 'aip_s3_uri' required.")

        if aip_uuid and not aip_s3_key:
            aip = self.get_aip_from_uuid(aip_uuid)
            aip_s3_key = aip.aip_s3_key

        if not aip_s3_key:
            raise ValueError(
                "AIP S3 URI not found or provided based on inputs aip_uuid: "
                f"{aip_uuid}, aip_s3_key: {aip_s3_key}"
            )

        # return cached results if available
        if aip_s3_key in self._aip_inventories:
            return self._aip_inventories[aip_s3_key]

        query = """
        select
            last_modified_date,
            filename,
            key,
            checksum_algorithm
        from inventory

        -- ensures data is only for most recent form of record and not deleted
        where is_latest
        and not is_delete_marker

        -- lastly, filter to our AIP prefix
        and key like $aip_s3_key;
        """
        aip_inventory_df = self.query_inventory(
            query,
            params={"aip_s3_key": f"{aip_s3_key}/data/%"},
        )

        self._aip_inventories[aip_s3_key] = aip_inventory_df
        return aip_inventory_df
