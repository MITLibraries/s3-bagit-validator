# ruff: noqa: D417

import base64
import binascii
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import boto3

if TYPE_CHECKING:
    from mypy_boto3_s3.client import S3Client as BotoS3Client
    from mypy_boto3_s3.type_defs import HeadObjectOutputTypeDef

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
        key = parsed.path.removeprefix("/")
        return bucket, key

    @classmethod
    def folder_exists(cls, s3_uri: str) -> bool:
        """Ensure that an S3 folder exists.

        This is performed by looking for an object that begins with this prefix,
        effectively demonstrating this is an S3 "folder" (though really just a prefix).
        Theoretically, it's possible this could be a zero-byte object "folder" and NOT
        contain any child objects, but this would still satisfy this method of detecting
        a "folder-like" object at this URI.
        """
        bucket, prefix = cls.parse_s3_uri(s3_uri)
        prefix = prefix.removesuffix("/") + "/"
        s3_client = cls.get_client()
        objects = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=1)

        # if "Contents" present in response, assume either child objects under this
        # prefix or this is an empty folder; either case indicating presence of a folder
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
    def read_s3_object_head(cls, s3_uri: str) -> "HeadObjectOutputTypeDef":
        """Read object head."""
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = cls.get_client()
        return s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED")

    @classmethod
    def read_s3_object(cls, s3_uri: str) -> str:
        """Read object and return contents as a string."""
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = cls.get_client()

        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read().decode("utf-8")

    @classmethod
    def read_s3_object_byte_range(
        cls,
        bucket: str,
        key: str,
        file_size: int,
        chunk_index: int,
        chunk_size: int,
    ) -> bytes:
        """Download a byte range chunk from an S3 object.

        This method calculates the start/end byte ranges based on the file size, chunk
        size, and chunk index requested.
        """
        s3_client = cls.get_client()

        start = chunk_index * chunk_size
        end = min(start + chunk_size, file_size)
        range_header = f"bytes={start}-{end - 1}"

        resp = s3_client.get_object(Bucket=bucket, Key=key, Range=range_header)
        return resp["Body"].read()

    @staticmethod
    def _decode_base64_sha256(base64_checksum: str | bytes) -> str:
        binary_checksum = base64.b64decode(base64_checksum)
        return binascii.hexlify(binary_checksum).decode("ascii")

    @classmethod
    def get_object_checksum(
        cls,
        s3_uri: str,
        size: int | None,
        has_sha256_checksum: bool | None = None,
    ) -> str:
        """Get SHA256 checksum for an S3 object.

        Object size and current checksum algorithm can be determined from S3 inventory
        data and passed here to improve performance and reduce API calls, but if unknown,
        a HEAD request is performed that retrieves this information.

        The mechanism by which we get a checksum for a file varies per the S3 object:

            - case 1: S3 object size >= 5gb
                - we must calculate a checksum manually from the object bytes
                - files this large cannot be copied via boto3.s3.copy_object(), and thus
                we cannot get a checksum per that approach
                - moreover, files this large cannot have "full" SHA256 checksums in AWS,
                only "composite" which is not the same as a Bagit checksum for the file

            - case 2: S3 object does not have a SHA256 checksum in metadata
                - if the file is < 5gb, we can use boto3.s3.copy_object() to copy the file
                 over itself, returning a SHA256 checksum in the process and saving it to
                 the object for future use

            - case 3: S3 object has a SHA256 checksum available
                - the object metadata already has a SHA256 checksum, use it
        """
        if size is None or has_sha256_checksum is None:
            object_head = cls.read_s3_object_head(s3_uri)
            size = object_head["ContentLength"]
            has_sha256_checksum = "SHA256" in object_head

        try:
            if size > 5 * 1024 * 1024 * 1024:  # 5 GB
                base64_checksum = cls.calculate_checksum_for_object(s3_uri)
            elif not has_sha256_checksum:
                base64_checksum = cls.generate_checksum_for_object(s3_uri)
            else:
                base64_checksum = cls.get_checksum_for_object(s3_uri)

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"Initial failure to get checksum: '{exc}', "
                "calculating from object bytes."
            )
            base64_checksum = cls.calculate_checksum_for_object(s3_uri)

        return cls._decode_base64_sha256(base64_checksum)

    @classmethod
    def calculate_checksum_for_object(
        cls,
        s3_uri: str,
        window_size: int = 40,
        chunk_size: int = 10 * 1024 * 1024,  # 10 MB
    ) -> str:
        """Calculate SHA256 checksum for an S3 object.

        This method is useful for objects >= 5gb, where boto3's copy_object() is not
        supported (used by class method generate_checksum_for_object()).  Instead, we are
        forced to calculate a checksum ourselves based on the content of the file.

        This method streams byte ranges in PARALLEL, but then hashes the bytes in ORDER,
        producing an accurate checksum.  This is sometimes called a "Scatter/Gather"
        approach, common in map reduce pipelines.  By using ThreadPoolExecutor.map(), we
        are guaranteed that we are hashing the bytes in order from the original file,
        while still performing some parallel downloading of bytes which considerably
        speeds up the process.

        This method does not ever store the full file in memory.  The memory pressure
        exerted is roughly equal to window_size * chunk_size (e.g. 40 * 10mb = 400mb).

        Args:
            - s3_uri: [str] S3 URI of object
            - window_size: [int] Number of chunks to download and hash in parallel
            - chunk_size: [int] Size in bytes for each chunk of the file downloaded
        """
        logger.debug(f"Calculating checksum for: {s3_uri}")
        start_time = time.perf_counter()
        bucket, key = cls.parse_s3_uri(s3_uri)

        file_size = cls.read_s3_object_head(s3_uri)["ContentLength"]
        num_chunks = (file_size + chunk_size - 1) // chunk_size
        hasher = hashlib.sha256()

        with ThreadPoolExecutor(max_workers=window_size) as executor:
            # prepare list of byte ranges for chunks that will
            # get passed to .download_object_byte_range()
            download_chunk_args = [
                (bucket, key, file_size, chunk_index, chunk_size)
                for chunk_index in range(num_chunks)
            ]

            # execute downloads in parallel, but receive results
            # in order via usage of .map()
            for chunk_index, chunk_data in enumerate(
                executor.map(
                    lambda args: cls.read_s3_object_byte_range(*args),
                    download_chunk_args,
                )
            ):
                # update checksum based on next contiguous chunk of bytes
                hasher.update(chunk_data)

                # log progress at roughly 10% intervals
                progress_percentage = ((chunk_index + 1) / num_chunks) * 100
                if progress_percentage % 10 < (1 / num_chunks) * 100:
                    logger.debug(
                        f"{int(progress_percentage)}% "
                        f"({(chunk_index + 1)}/{num_chunks} chunks) "
                        f"complete for '{s3_uri}'"
                    )

        base64_checksum = base64.b64encode(hasher.digest()).decode("ascii")
        logger.debug(
            f"Checksum calculation elapsed: {time.perf_counter() - start_time:.2f}s, "
            f"s3_uri: '{s3_uri}'."
        )
        return base64_checksum

    @classmethod
    def generate_checksum_for_object(cls, s3_uri: str) -> str:
        """Generate a SHA256 checksum for an S3 object by copying it over itself.

        In addition to returning  the SHA256 checksum, this also saves the checksum to the
        object metadata such that it can be quickly retrieved in the future.
        """
        logger.debug(f"Generating checksum for: {s3_uri}")
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
        """Get the SHA256 checksum for an S3 object from its Metadata."""
        logger.debug(f"Getting checksum for: {s3_uri}")
        bucket, key = cls.parse_s3_uri(s3_uri)
        s3_client = cls.get_client()

        head_response = s3_client.head_object(
            Bucket=bucket, Key=key, ChecksumMode="ENABLED"
        )

        if "ChecksumSHA256" in head_response:
            return head_response["ChecksumSHA256"]
        raise ValueError(f"Object does not have a SHA256 checksum: {s3_uri}")
