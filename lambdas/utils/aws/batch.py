import logging
from typing import Any

import boto3

from lambdas.config import Config
from lambdas.utils.aws import S3Client

logger = logging.getLogger(__name__)

CONFIG = Config()


class S3BatchOperationClient:
    """Client to create and manage S3 Batch Operation jobs.

    This client handles the creation and submission of S3 Batch Operation jobs,
    using manifest files to specify objects for processing.
    """

    def __init__(self) -> None:
        """Initialize the S3 Batch Operation client."""
        self.s3_client = S3Client()
        self.s3control = boto3.client("s3control")

    def create_job(
        self,
        manifest_uri: str,
        role_arn: str,
        account_id: str,
        current_date_str: str,
        priority: int = 10,
        report_bucket: str | None = None,
    ) -> dict[str, Any]:
        """Create an S3 Batch Operation job.

        Args:
            manifest_uri: S3 URI of the manifest file (e.g., 's3://bucket/key')
            role_arn: IAM role ARN for executing the job
            account_id: AWS account ID
            current_date_str: Current date string for job description and idempotency
            priority: Job priority (1-255)
            report_bucket: Optional separate bucket for job reports
        """
        manifest_etag = self.s3_client.read_s3_object_head(manifest_uri)["ETag"]
        manifest_bucket, manifest_key = self.s3_client.parse_s3_uri(manifest_uri)

        if not report_bucket:
            report_bucket = manifest_bucket

        description = f"Compute SHA256 checksums {current_date_str}"

        try:
            response = self.s3control.create_job(
                AccountId=account_id,
                ConfirmationRequired=False,
                Description=description,
                Priority=priority,
                RoleArn=role_arn,
                Manifest={
                    "Spec": {
                        "Format": "S3BatchOperations_CSV_20180820",
                        "Fields": ["Bucket", "Key"],
                    },
                    "Location": {
                        "ObjectArn": f"arn:aws:s3:::{manifest_bucket}/{manifest_key}",
                        "ETag": manifest_etag,
                    },
                },
                Operation={
                    "S3ComputeObjectChecksum": {
                        "ChecksumAlgorithm": "SHA256",
                        "ChecksumType": "FULL_OBJECT",
                    }
                },
                Report={
                    "Bucket": f"arn:aws:s3:::{report_bucket}",
                    "Format": "Report_CSV_20180820",
                    "Enabled": True,
                    "Prefix": "batch",
                    "ReportScope": "AllTasks",
                    "ExpectedBucketOwner": account_id,
                },
                # Unique token for idempotency
                ClientRequestToken=f"batch-job-{current_date_str}",
            )

            logger.info(
                f"Created S3 Batch Operation job: {response['JobId']}, {description}"
            )

            return {
                "job_id": response["JobId"],
                "status": "Created",
                "description": description,
                "response": response,
            }

        except Exception:
            logger.exception("Error creating S3 Batch Operation job: ")
            raise
