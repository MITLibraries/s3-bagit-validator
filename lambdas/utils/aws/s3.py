import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import boto3

if TYPE_CHECKING:
    from mypy_boto3_s3.client import S3Client as BotoS3Client

logger = logging.getLogger(__name__)


class S3Client:

    @classmethod
    def get_client(cls) -> "BotoS3Client":
        return boto3.client("s3")

    @staticmethod
    def parse_s3_uri(s3_uri: str) -> tuple[str, str]:
        """Parse bucket and key from a full S3 URI."""
        parsed = urlparse(s3_uri)
        if parsed.scheme != "s3":
            raise ValueError(f"Invalid S3 URI scheme: {s3_uri}")

        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        return bucket, key

    @classmethod
    def folder_exists(cls, s3_uri: str) -> bool:
        """Ensure that an S3 folder exists.

        This is performed by looking for an object that exists under this prefix,
        effectively demonstrating this is an S3 "folder" (though really just a prefix).
        """
        bucket, prefix = cls.parse_s3_uri(s3_uri)
        prefix = prefix.removesuffix("/") + "/"
        s3_client = cls.get_client()

        # retrieve max of one object with this prefix
        objects = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1)

        # if contents present, assume there are child objects
        return "Contents" in objects

    @classmethod
    def list_objects_recursive(cls, s3_uri: str) -> list[str]:
        """List object S3 URIs recursively given a root S3 URI.

        Returns:
            - full S3 URI for each discovered object
        """
        bucket, prefix = cls.parse_s3_uri(s3_uri)
        prefix = prefix.removesuffix("/") + "/"
        s3_client = cls.get_client()

        object_uris = []
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            if "Contents" in page:
                for obj in page["Contents"]:
                    # skip folders (objects with trailing slash "/")
                    if not obj["Key"].endswith("/"):
                        object_uris.append(f"s3://{bucket}/{obj['Key']}")  # noqa: PERF401

        return object_uris

    @classmethod
    def read_s3_object(cls, s3_uri: str) -> str:
        """Read object and return contents as a string."""
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = cls.get_client()

        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read().decode("utf-8")

    @classmethod
    def generate_checksum_for_object(cls, s3_uri: str) -> str:
        """Generate a SHA256 checksum for an S3 object by copying it over itself."""
        logger.info(f"generating checksum for: {s3_uri}")
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = cls.get_client()

        copy_response = s3_client.copy_object(
            Bucket=bucket,
            Key=key,
            CopySource={"Bucket": bucket, "Key": key},
            ChecksumAlgorithm="SHA256",
        )
        return copy_response["CopyObjectResult"]["ChecksumSHA256"]

    @classmethod
    def get_checksum_for_object(cls, s3_uri: str) -> str:
        """Get the SHA256 checksum for an S3 object."""
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = boto3.client("s3")

        head_response = s3_client.head_object(
            Bucket=bucket, Key=key, ChecksumMode="ENABLED"
        )

        if "ChecksumSHA256" in head_response:
            return head_response["ChecksumSHA256"]
        raise ValueError(f"Object does not have a SHA256 checksum: {s3_uri}")
