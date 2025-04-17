import base64
import binascii
import concurrent.futures
import json
import logging
import re
from dataclasses import asdict, dataclass
from threading import Lock
from time import perf_counter

import pandas as pd
from botocore.exceptions import ClientError

from lambdas.config import Config
from lambdas.exceptions import AIPValidationError
from lambdas.utils.aws import S3Client, S3InventoryClient

logger = logging.getLogger(__name__)

CONFIG = Config()


@dataclass
class ValidationResponse:
    """AIP validation response data.

    Attributes:
        s3_uri: S3 URI of Bagit AIP validated
        valid: AIP has all files and all have expected checksums
        elapsed: time in seconds to perform validation
        manifest: dictionary of manifest file to its checksum
        error: string of error(s) if encountered during validation
        error_details: dictionary of details related to validation error(s)
    """

    s3_uri: str
    valid: bool
    elapsed: float
    manifest: dict[str, str] | None = None
    error: str | None = None
    error_details: dict | None = None

    def to_dict(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> dict:
        output = asdict(self)
        if include:
            output = {k: v for k, v in output.items() if k in include}
        if exclude:
            output = {k: v for k, v in output.items() if k not in exclude}
        return output

    def to_json(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> str:
        return json.dumps(self.to_dict(include=include, exclude=exclude))


class AIP:
    """Class to represent and validate a Bagit AIP stored in S3."""

    def __init__(
        self,
        s3_uri: str,
        s3_inventory_client: S3InventoryClient | None = None,
    ):
        self.s3_uri = s3_uri.removesuffix("/")
        self.s3_bucket, self.s3_key = S3Client.parse_s3_uri(self.s3_uri)

        self.s3_client = S3Client()
        self.s3_inventory_client = s3_inventory_client or S3InventoryClient()

        self.manifest_df: pd.DataFrame | None = None
        self.files: list[str] | None = None
        self.s3_inventory: pd.DataFrame | None = None
        self.file_checksums: dict = {}

    @property
    def data_files(self) -> list[str] | None:
        if not self.files:
            return None
        return [file for file in self.files if file.startswith("data/")]

    @property
    def manifest_as_dict(self) -> dict | None:
        if self.manifest_df is not None:
            return dict(
                zip(
                    self.manifest_df["filepath"],
                    self.manifest_df["checksum"],
                    strict=True,
                )
            )
        return None

    @classmethod
    def from_s3_uri(cls, s3_uri: str) -> "AIP":
        """Init AIP validator from AIP S3 URI."""
        return cls(s3_uri=s3_uri)

    @classmethod
    def from_uuid(cls, aip_uuid: str) -> "AIP":
        """Init AIP validator from AIP UUID.

        An instance of the S3InventoryClient is passed to reuse any cached query results.
        """
        s3_inventory_client = S3InventoryClient()
        aip = s3_inventory_client.get_aip_from_uuid(aip_uuid)
        return cls(s3_uri=aip.aip_s3_uri, s3_inventory_client=s3_inventory_client)

    def validate(self, num_workers: int | None = None) -> ValidationResponse:
        """Validate that AIP manifest files and checksums match the AIP in S3.

        Flow:
        1. Check that AIP exists as folder in S3
            - if not, RETURN FAILURE
        2. Retrieve Bagit files manifest from AIP
        3. Ensure that all files from Bagit manifest are in S3; no more, no less
            - if not, RETURN FAILURE
        4. Retrieve S3 inventory for this AIP and ensure that each file in manifest has
            a checksum in S3
        5. For those missing checksums, generate them by copying object over itself in S3
        6. For each file in Bagit manifest, ensure manifest checksum matches S3 checksum
        7. Return response

        If any validation step fails it throws an AIPValidationError exception which is
        caught and a response is returned, otherwise a success response is returned.
        """
        start_time = perf_counter()

        if not num_workers:
            num_workers = CONFIG.checksum_num_workers

        try:
            self._check_aip_s3_folder_exists()
            self.manifest_df = self._parse_aip_manifest()
            self.files = self._get_aip_files()
            self._check_aip_files_match_manifest()
            self.s3_inventory = self._get_aip_s3_inventory()
            self.file_checksums = self._get_aip_file_checksums(num_workers=num_workers)
            self._check_checksums()

            return ValidationResponse(
                s3_uri=self.s3_uri,
                valid=True,
                elapsed=round(perf_counter() - start_time, 2),
                manifest=self.manifest_as_dict,
            )

        except AIPValidationError as exception:

            return ValidationResponse(
                s3_uri=self.s3_uri,
                valid=False,
                elapsed=round(perf_counter() - start_time, 2),
                manifest=self.manifest_as_dict,
                error=str(exception),
                error_details=exception.error_details,
            )

    def _check_aip_s3_folder_exists(self) -> None:
        if not self.s3_client.folder_exists(self.s3_uri):
            raise AIPValidationError(
                f"Bagit AIP folder not found in S3: {self.s3_uri}",
                error_details={"type": "aip_folder_not_found", "s3_uri": self.s3_uri},
            )

    def _parse_aip_manifest(self) -> pd.DataFrame:
        """Read manifest-sha256.txt from AIP."""
        try:
            manifest_data = self.s3_client.read_s3_object(
                f"{self.s3_uri}/manifest-sha256.txt"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchKey":
                raise AIPValidationError(
                    "Could not find 'manifest-sha256.txt' for AIP.",
                    error_details={
                        "type": "manifest_not_found",
                        "s3_uri": f"{self.s3_uri}/manifest-sha256.txt",
                        "error_code": exc.response["Error"]["Code"],
                    },
                ) from exc
        lines = manifest_data.strip().split("\n")
        data = []
        for line in lines:
            checksum, filepath = re.split(r"\s{2}", line, maxsplit=1)
            data.append({"checksum": checksum, "filepath": filepath})
        return pd.DataFrame(data)

    def _get_aip_files(self) -> list[str]:
        """Get list of all files, recursively, under AIP root in S3."""
        uris = self.s3_client.list_objects_recursive(self.s3_uri)
        return [uri.removeprefix(self.s3_uri).removeprefix("/") for uri in uris]

    def _check_aip_files_match_manifest(self) -> None:
        """Verify that files in the manifest and AIP data match exactly."""
        if self.manifest_df is None:
            raise ValueError("Bagit manifest data not found")
        if self.data_files is None:
            raise ValueError("Bagit data files not found")

        manifest_files = set(self.manifest_df["filepath"])
        aip_data_files = set(self.data_files)
        exclude_patterns = [".DS_Store"]

        missing_in_aip = {
            f
            for f in (manifest_files - aip_data_files)
            if not any(f.endswith(pattern) for pattern in exclude_patterns)
        }
        missing_in_manifest = {
            f
            for f in (aip_data_files - manifest_files)
            if not any(f.endswith(pattern) for pattern in exclude_patterns)
        }

        if missing_in_aip:
            missing_files = list(missing_in_aip)
            raise AIPValidationError(
                "Files found in manifest but missing from AIP: "
                + json.dumps(missing_files),
                error_details={
                    "type": "files_missing_in_aip",
                    "missing_files": missing_files,
                },
            )
        if missing_in_manifest:
            missing_files = list(missing_in_manifest)
            raise AIPValidationError(
                "Files found in AIP but missing from manifest: "
                + json.dumps(missing_files),
                error_details={
                    "type": "files_missing_in_manifest",
                    "missing_files": missing_files,
                },
            )

    def _get_aip_s3_inventory(self) -> pd.DataFrame:
        """Query S3 Inventory for list of files."""
        logger.info("Retrieving S3 Inventory data")
        inventory_df = self.s3_inventory_client.get_aip_inventory(aip_s3_key=self.s3_key)

        if len(inventory_df) == 0:
            raise AIPValidationError(
                f"S3 Inventory data not found for S3 key: '{self.s3_key}'",
                error_details={"type": "s3_inventory_not_found", "s3_key": self.s3_key},
            )

        # index by S3 key
        return inventory_df.set_index("key")

    @staticmethod
    def _decode_base64_sha256(base64_checksum: str | bytes) -> str:
        binary_checksum = base64.b64decode(base64_checksum)
        return binascii.hexlify(binary_checksum).decode("ascii")

    def _get_aip_file_checksums(
        self, num_workers: int = CONFIG.checksum_num_workers
    ) -> dict[str, str]:
        """Get checksums for all files listed in Bagit manifest.

        This process is performed in parallel via threads by the worker function
        'process_file_worker' which updates a local dictionary of file-to-checksum.

        The mechanism by which we get a checksum for a file varies per the S3 object:

            - case 1: S3 objects >= 5gb
                - use S3Client.calculate_checksum_for_large_object()
                - we must calculate a checksum manually from the object bytes
                - files this large cannot be copied via boto3.s3.copy_object(), and thus
                we cannot get a checksum per that approach
                - moreover, files this large cannot have "full" SHA256 checksums in AWS,
                only "composite" which is not the same as a Bagit checksum for the file

            - case 2: S3 object does not have a SHA256 checksum available
                - use S3Client.generate_checksum_for_object()
                - if the file is < 5gb, we can use boto3.s3.copy_object() to copy the file
                 over itself, returning a SHA256 checksum in the process and saving it to
                 the object for future use

            - case 3: S3 object has a SHA256 checksum available
                - use S3Client.get_checksum_for_object()
                - the object already has a SHA256 checksum, use it
        """
        if self.manifest_df is None:
            raise ValueError("Bagit manifest data not found")
        if self.s3_inventory is None:
            raise ValueError("S3 Inventory data not found")

        file_checksums = {}
        file_checksums_lock = Lock()

        def process_file_worker(row: pd.Series) -> None:
            filepath = row.filepath
            s3_uri = f"{self.s3_uri}/{filepath}"
            inventory_row = self.s3_inventory.loc[  # type: ignore[union-attr]
                f"{self.s3_key}/{filepath}"
            ]

            # derive a SHA256 checksum for file
            ## S3 objects >= 5gb
            if inventory_row["size"] > 5 * 1024 * 1024 * 1024:  # 5 GB
                base64_checksum = self.s3_client.calculate_checksum_for_large_object(
                    s3_uri
                )
            ## S3 object does not have a SHA256 checksum via metadata
            elif inventory_row["checksum_algorithm"] != "SHA256":
                base64_checksum = self.s3_client.generate_checksum_for_object(s3_uri)
            ## S3 object has a SHA256 checksum available via metadata
            else:
                base64_checksum = self.s3_client.get_checksum_for_object(s3_uri)

            # convert base64 form to ascii
            checksum = self._decode_base64_sha256(base64_checksum)
            logger.debug(f"AIP file: '{filepath}', checksum: '{checksum}'")

            # save file:checksum dictionary
            with file_checksums_lock:
                file_checksums[filepath] = checksum

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(process_file_worker, row)
                for _, row in self.manifest_df.iterrows()
            ]

            # report on futures as they complete, logging approximately each 10%
            total_futures = len(futures)
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                    completed += 1
                    if (
                        completed % max(1, total_futures // 10) == 0
                        or completed == total_futures
                    ):
                        logger.info(
                            f"Processed {completed}/{total_futures} "
                            f"files ({(completed / total_futures) * 100:.1f}%)"
                        )
                except Exception:
                    logger.exception("Error getting checksum for file")
                    raise

        return file_checksums

    def _check_checksums(self) -> None:
        """Check that Bagit manifest checksums match checksums retrieved from S3."""
        if self.manifest_df is None:
            raise ValueError("Bagit manifest data not found")

        mismatches = []
        for _, row in self.manifest_df.iterrows():
            if row.checksum != self.file_checksums[row.filepath]:
                mismatches.append(row.filepath)
        if mismatches:
            raise AIPValidationError(
                """Mismatched checksums for files""",
                error_details={
                    "type": "checksum_mismatch",
                    "mismatched_files": mismatches,
                    "manifest_checksums": {
                        row.filepath: row.checksum
                        for _, row in self.manifest_df.iterrows()
                        if row.filepath in mismatches
                    },
                    "s3_checksums": {
                        filepath: self.file_checksums[filepath] for filepath in mismatches
                    },
                },
            )
