# ruff: noqa: PD901, DTZ001, PLR2004, SLF001, ARG002, BLE001

import concurrent.futures
import datetime
import os
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from lambdas.utils.aws.s3_inventory import S3InventoryClient


class TestS3InventoryClientInitialization:
    def test_init_env_var_inventory_uris(self):
        client = S3InventoryClient()
        assert client.inventory_uris == os.environ["S3_INVENTORY_LOCATIONS"].split(",")

    def test_init_custom_inventory_uris(self):
        custom_uris = ["s3://bucket1/inventory", "s3://bucket2/inventory"]
        client = S3InventoryClient(inventory_uris=custom_uris)
        assert client.inventory_uris == custom_uris


class TestS3InventoryClientDateExtraction:
    def test_extract_dt_date_from_s3_key_valid(self):
        s3_uri = "s3://example-bucket/inventory/dt=2023-04-15-00-00/symlink.txt"
        result = S3InventoryClient.extract_dt_date_from_s3_key(s3_uri)
        assert isinstance(result, datetime.datetime)
        assert result == datetime.datetime(2023, 4, 15, 0, 0)

    def test_extract_dt_date_from_s3_key_invalid(self):
        s3_uri = "s3://example-bucket/inventory/missing-dt-parameter/symlink.txt"
        with pytest.raises(ValueError, match="Could not parse datetime partition"):
            S3InventoryClient.extract_dt_date_from_s3_key(s3_uri)


class TestS3InventoryClientParquetFiles:
    def test_get_single_inventory_parquet_files(self, mock_s3_client):
        """Test retrieving parquet files for a single inventory."""
        client = S3InventoryClient()

        with patch.object(client.s3_client, "list_objects_recursive") as mock_list:
            mock_list.return_value = [
                "s3://bucket/inventory/dt=2023-04-15-00-00/symlink.txt",
                "s3://bucket/inventory/dt=2023-04-14-00-00/symlink.txt",
            ]

            with patch.object(client.s3_client, "read_s3_object") as mock_read:
                mock_read.return_value = "s3://bucket/inventory/dt=2023-04-15-00-00/data1.parquet\ns3://bucket/inventory/dt=2023-04-15-00-00/data2.parquet"

                result = client.get_single_inventory_parquet_files(
                    "s3://bucket/inventory"
                )

                # verify most recent symlink file was used to get list of parquet files
                mock_list.assert_called_once_with("s3://bucket/inventory")
                mock_read.assert_called_once_with(
                    "s3://bucket/inventory/dt=2023-04-15-00-00/symlink.txt"
                )

                assert len(result) == 2
                assert "s3://bucket/inventory/dt=2023-04-15-00-00/data1.parquet" in result
                assert "s3://bucket/inventory/dt=2023-04-15-00-00/data2.parquet" in result

    def test_get_single_inventory_parquet_files_inventory_missing_or_empty(
        self, caplog, mock_s3_client
    ):
        client = S3InventoryClient()
        with patch.object(client.s3_client, "list_objects_recursive") as mock_list:
            mock_list.return_value = []
            result = client.get_single_inventory_parquet_files("s3://bucket/inventory")
            assert result == []
            assert "No symlink.txt files found for inventory location" in caplog.text

    def test_get_all_inventory_parquet_files(self):
        client = S3InventoryClient(
            inventory_uris=["s3://bucket1/inventory", "s3://bucket2/inventory"]
        )

        with patch.object(
            client, "get_single_inventory_parquet_files"
        ) as mock_get_single:
            mock_get_single.side_effect = [
                [
                    "s3://bucket1/inventory/data1.parquet",
                    "s3://bucket1/inventory/data2.parquet",
                ],
                ["s3://bucket2/inventory/data1.parquet"],
            ]

            result = client.get_all_inventory_parquet_files()

            assert mock_get_single.call_count == 2
            mock_get_single.assert_any_call("s3://bucket1/inventory")
            mock_get_single.assert_any_call("s3://bucket2/inventory")

            assert len(result) == 3
            assert "s3://bucket1/inventory/data1.parquet" in result
            assert "s3://bucket1/inventory/data2.parquet" in result
            assert "s3://bucket2/inventory/data1.parquet" in result

            client.get_all_inventory_parquet_files()
            assert mock_get_single.call_count == 2

    def test_get_all_inventory_parquet_files_error_handling(self):
        client = S3InventoryClient(inventory_uris=["s3://bucket/inventory"])
        with patch.object(
            client, "get_single_inventory_parquet_files"
        ) as mock_get_single:
            mock_get_single.side_effect = Exception("Test error")
            with pytest.raises(RuntimeError, match="Error processing inventory"):
                client.get_all_inventory_parquet_files()

    def test_get_all_inventory_parquet_files_empty_result(self):
        client = S3InventoryClient(inventory_uris=["s3://bucket/inventory"])
        with patch.object(
            client, "get_single_inventory_parquet_files"
        ) as mock_get_single:
            mock_get_single.return_value = []  # mock empty list
            with pytest.raises(RuntimeError, match="Could not find any parquet files"):
                client.get_all_inventory_parquet_files()


class TestS3InventoryClientQueries:
    def test_query_inventory(self):
        client = S3InventoryClient()
        client._inventory_parquet_files = ["s3://bucket/inventory/data.parquet"]

        mock_conn = MagicMock()
        mock_df = pd.DataFrame({"column1": [1, 2], "column2": ["a", "b"]})
        mock_conn.query.return_value.to_df.return_value = mock_df

        with patch("duckdb.connect") as mock_connect:
            mock_connect.return_value.__enter__.return_value = mock_conn

            result = client.query_inventory("SELECT * FROM inventory")

            mock_connect.assert_called_once()
            mock_conn.query.assert_called_once_with(
                "SELECT * FROM inventory", params=None
            )

            assert result.equals(mock_df)

    def test_query_inventory_with_params(self):
        """Test querying inventory data with parameters."""
        client = S3InventoryClient()
        client._inventory_parquet_files = ["s3://bucket/inventory/data.parquet"]

        mock_conn = MagicMock()
        mock_df = pd.DataFrame({"column1": [1], "column2": ["filtered"]})
        mock_conn.query.return_value.to_df.return_value = mock_df

        with patch("duckdb.connect") as mock_connect:
            mock_connect.return_value.__enter__.return_value = mock_conn

            params = {"filter_value": "test"}
            result = client.query_inventory(
                "SELECT * FROM inventory WHERE key = $filter_value", params=params
            )

            mock_conn.query.assert_called_once_with(
                "SELECT * FROM inventory WHERE key = $filter_value", params=params
            )

            assert result.equals(mock_df)


class TestS3InventoryClientAIPOperations:
    def test_get_aips_df(self):
        """Test retrieving DataFrame of all AIPs."""
        client = S3InventoryClient()
        mock_df = pd.DataFrame(
            {
                "bucket": ["test-bucket", "test-bucket"],
                "aip_uuid": ["uuid1", "uuid2"],
                "aip_s3_key": ["prefix/uuid1", "prefix/uuid2"],
                "aip_s3_uri": [
                    "s3://test-bucket/prefix/uuid1",
                    "s3://test-bucket/prefix/uuid2",
                ],
                "aip_files_count": [5, 3],
                "total_size_bytes": [1024, 2048],
                "earliest_file_date": [
                    datetime.datetime(2023, 1, 1),
                    datetime.datetime(2023, 2, 1),
                ],
                "latest_file_date": [
                    datetime.datetime(2023, 1, 10),
                    datetime.datetime(2023, 2, 10),
                ],
            }
        )

        with patch.object(client, "query_inventory") as mock_query:
            mock_query.return_value = mock_df
            result = client.get_aips_df()

            assert result.equals(mock_df)

            # assert results cached and reused
            assert client._aips_df is not None
            client.get_aips_df()
            mock_query.assert_called_once()

    def test_get_aip_from_uuid_success(self):
        """Test retrieving an AIP by UUID."""
        client = S3InventoryClient()
        mock_df = pd.DataFrame(
            {
                "aip_uuid": ["test-uuid", "other-uuid"],
                "bucket": ["test-bucket", "test-bucket"],
                "aip_s3_key": ["prefix/pickles-test-uuid", "prefix/bananas-other-uuid"],
            }
        )

        with patch.object(client, "get_aips_df") as mock_get_aips:
            mock_get_aips.return_value = mock_df

            result = client.get_aip_from_uuid("test-uuid")

            assert result["bucket"] == "test-bucket"
            assert result["aip_s3_key"] == "prefix/pickles-test-uuid"

    def test_get_aip_from_uuid_not_found(self):
        """Test error when AIP UUID is not found."""
        client = S3InventoryClient()

        mock_df = pd.DataFrame(
            {
                "aip_uuid": ["uuid1", "uuid2"],
                "bucket": ["test-bucket", "test-bucket"],
            }
        )

        with patch.object(client, "get_aips_df") as mock_get_aips:
            mock_get_aips.return_value = mock_df

            with pytest.raises(ValueError, match="AIP UUID 'missing-uuid' not found"):
                client.get_aip_from_uuid("missing-uuid")

    def test_get_aip_from_uuid_multiple_entries(self):
        """Test error when multiple entries are found for the same UUID."""
        client = S3InventoryClient()

        mock_df = pd.DataFrame(
            {
                "aip_uuid": ["duplicate-uuid", "duplicate-uuid"],
                "bucket": ["test-bucket", "other-bucket"],
                "aip_s3_key": ["prefix/duplicate-uuid", "other-prefix/duplicate-uuid"],
            }
        )

        with patch.object(client, "get_aips_df") as mock_get_aips:
            mock_get_aips.return_value = mock_df

            with pytest.raises(TypeError, match="Multiple entries found for AIP UUID"):
                client.get_aip_from_uuid("duplicate-uuid")

    def test_get_aip_inventory_with_uuid(self):
        """Test retrieving AIP inventory using UUID."""
        client = S3InventoryClient()
        aip_data = pd.Series(
            {
                "aip_uuid": "test-uuid",
                "aip_s3_key": "prefix/test-uuid",
                "bucket": "test-bucket",
            }
        )
        inventory_df = pd.DataFrame(
            {
                "last_modified_date": [datetime.datetime(2023, 1, 1)],
                "filename": ["data.parquet"],
                "key": ["prefix/test-uuid/data/file.txt"],
                "checksum_algorithm": ["SHA256"],
            }
        )

        with patch.object(client, "get_aip_from_uuid") as mock_get_aip:
            mock_get_aip.return_value = aip_data

            with patch.object(client, "query_inventory") as mock_query:
                mock_query.return_value = inventory_df

                result = client.get_aip_inventory(aip_uuid="test-uuid")

                mock_get_aip.assert_called_once_with("test-uuid")
                mock_query.assert_called_once()

                query_params = mock_query.call_args[1]["params"]
                assert query_params["aip_s3_key"] == "prefix/test-uuid/data/%"

                assert result.equals(inventory_df)
                assert "prefix/test-uuid" in client._aip_inventories
                assert client._aip_inventories["prefix/test-uuid"].equals(inventory_df)

    def test_get_aip_inventory_with_s3_key(self):
        """Test retrieving AIP inventory using S3 key."""
        client = S3InventoryClient()
        inventory_df = pd.DataFrame(
            {
                "last_modified_date": [datetime.datetime(2023, 1, 1)],
                "filename": ["data.parquet"],
                "key": ["prefix/test-uuid/data/file.txt"],
                "checksum_algorithm": ["SHA256"],
            }
        )

        with patch.object(client, "query_inventory") as mock_query:
            mock_query.return_value = inventory_df

            result = client.get_aip_inventory(aip_s3_key="prefix/test-uuid")

            mock_query.assert_called_once()
            assert (
                mock_query.call_args[1]["params"]["aip_s3_key"]
                == "prefix/test-uuid/data/%"
            )

            assert result.equals(inventory_df)

    def test_get_aip_inventory_cache(self):
        """Test AIP inventory caching."""
        client = S3InventoryClient()
        aip_key = "prefix/test-uuid"
        inventory_df = pd.DataFrame({"key": ["test"]})
        client._aip_inventories[aip_key] = inventory_df
        result = client.get_aip_inventory(aip_s3_key=aip_key)
        assert result.equals(inventory_df)

    def test_get_aip_inventory_missing_parameters(self):
        client = S3InventoryClient()
        with pytest.raises(
            ValueError, match="Either 'aip_uuid' or 'aip_s3_uri' required"
        ):
            client.get_aip_inventory()


@pytest.mark.integration
class TestS3InventoryClientIntegration:

    def test_retrieval_of_inventory_aips(self):
        client = S3InventoryClient()
        aips_df = client.get_aips_df()
        assert isinstance(aips_df, pd.DataFrame)

    def test_retrieval_of_aip_inventory(self):
        """Test retrieval of Inventory data for a single AIP.

        To avoid hardcoding a UUID that might differ in different contexts, this assumes
        the first row in the AIPs retrieved from get_aips_df() has an inventory to
        retrieve.
        """
        client = S3InventoryClient()
        aips_df = client.get_aips_df()
        aip_inventory_df = client.get_aip_inventory(aip_uuid=aips_df.iloc[0].aip_uuid)
        assert isinstance(aip_inventory_df, pd.DataFrame)

    def test_concurrent_requests(self):
        """Test to demonstrate this approach supports many, small, parallel requests."""
        query = """
        select
            last_modified_date,
            count(last_modified_date) as count
        from inventory
        group by last_modified_date
        order by count(last_modified_date) desc
        ;
        """

        # run a single query to get a baseline result
        single_client = S3InventoryClient()
        single_result = single_client.query_inventory(query)
        assert isinstance(single_result, pd.DataFrame)
        assert not single_result.empty

        # setup 20 parallel client instances
        num_clients = 20
        clients = [S3InventoryClient() for _ in range(num_clients)]
        results = []

        # execute queries in parallel using threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
            futures = [
                executor.submit(client.query_inventory, query) for client in clients
            ]

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    pytest.fail(f"Concurrent query failed with exception: {exc}")

        assert len(results) == num_clients

        # concatenate all results and veriy row count is equal to x20 a single response
        combined_df = pd.concat(results)
        assert len(combined_df) == len(single_result) * num_clients
