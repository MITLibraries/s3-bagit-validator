import datetime
import logging

import boto3
import click
import smart_open

from lambdas.utils.aws.batch import S3BatchOperationClient
from lambdas.utils.aws.s3_inventory import S3InventoryClient

logger = logging.getLogger(__name__)


@click.command()
@click.argument("uuid")
@click.option(
    "--manifest-bucket",
    "-b",
    help="S3 bucket where the manifest file will be written",
)
@click.option("--role-arn", "-r", help="IAM role ARN for batch operations")
@click.option("--account-id", "-a", help="AWS account ID")
def create_compute_sha256_job(
    uuid: str, manifest_bucket: str, role_arn: str, account_id: str
) -> None:
    """Create a S3 Batch Operation job to compute SHA256 checksums for an AIP."""
    batch_client = S3BatchOperationClient()

    current_date_str = datetime.datetime.now(tz=datetime.UTC).strftime(
        "%Y-%m-%d-%H-%M-%S",
    )

    manifest_uri = write_manifest_from_uuid(uuid, manifest_bucket)

    try:
        response = batch_client.create_job(
            manifest_uri=manifest_uri,
            role_arn=role_arn,
            account_id=account_id,
            current_date_str=current_date_str,
        )
        logger.info(response)

    except Exception:
        logger.exception("Failed to process batch operation: ")
        raise


def write_manifest_from_uuid(uuid: str, manifest_bucket: str) -> str:
    """Generate a manifest file for a given AIP UUID using S3 Inventory data."""
    s3_inventory_client = S3InventoryClient()
    inventory = s3_inventory_client.get_aip_from_uuid(uuid)
    inventory_file_name = inventory["aip_s3_key"].replace("/", "-")
    manifest_uri = f"s3://{manifest_bucket}/{inventory_file_name}-inventory.csv"
    with smart_open.open(manifest_uri, "w") as csv_file:
        for key in get_nested_object_keys_from_s3_key(
            inventory["bucket"], inventory["aip_s3_key"]
        ):
            csv_file.write(f"{inventory['bucket']},{key}\n")
    return manifest_uri


def get_nested_object_keys_from_s3_key(bucket_name: str, key: str) -> list:
    """Retrieve all object keys under a specified S3 key."""
    files = []
    s3_client = boto3.client("s3")
    paginator = s3_client.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket_name, Prefix=key)
    for page in [page for page in pages if "Contents" in page]:
        files.extend([obj["Key"] for obj in page["Contents"]])
    return files


if __name__ == "__main__":
    create_compute_sha256_job()
