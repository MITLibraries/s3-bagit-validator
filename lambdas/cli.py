# ruff: noqa: TRY400

import concurrent.futures
import json
import logging
import time
from http import HTTPStatus
from threading import Lock
from typing import Any

import click
import numpy as np
import pandas as pd
import requests

from lambdas.config import Config, configure_logger

logger = logging.getLogger(__name__)
CONFIG = Config()


@click.group()
@click.pass_context
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    required=False,
    help="Flag for verbose output.",
)
def cli(ctx: click.Context, *, verbose: bool) -> None:
    """S3 BagIt Validator CLI."""
    ctx.ensure_object(dict)
    configure_logger(logging.getLogger(), verbose=verbose)
    ctx.obj["VERBOSE"] = verbose


@cli.command()
@click.pass_context
def ping(ctx: click.Context) -> None:
    """Ping deployed AWS lambda, ensure connection and authorization."""
    try:
        ping_response = requests.post(
            CONFIG.lambda_endpoint_url,
            json={
                "action": "ping",
                "challenge_secret": CONFIG.CHALLENGE_SECRET,
                "verbose": ctx.obj["VERBOSE"],
            },
            timeout=30,
        )

        if (
            ping_response.status_code == HTTPStatus.OK
            and ping_response.json()["response"] == "pong"
        ):
            click.echo(f"SUCCESS: {ping_response.text}.")
            ctx.exit(0)
        else:
            error_msg = f"ERROR: {ping_response.text}."
            click.echo(error_msg, err=True)
            ctx.exit(1)

    except requests.exceptions.ConnectTimeout:
        error_msg = "ERROR: timeout connecting; possible firewall restriction."
        click.echo(error_msg, err=True)
        ctx.exit(1)
    except requests.exceptions.RequestException as exc:
        error_msg = f"ERROR: {exc}"
        click.echo(error_msg, err=True)
        ctx.exit(1)


@cli.command()
@click.pass_context
@click.option("--aip-uuid", "-a", required=False, help="AIP UUID from Archivematica.")
@click.option("--s3-uri", "-u", required=False, help="Full S3 URI of AIP stored in S3.")
@click.option(
    "--details",
    "-d",
    required=False,
    is_flag=True,
    help="Return full AIP validation details as JSON to stdout instead of 'OK'.",
)
def validate(ctx: click.Context, aip_uuid: str, s3_uri: str, *, details: bool) -> None:
    """Validate a single AIP stored in S3 via the AIP UUID or S3 URI.

    The result is either 'OK' or the full validation response if the '--details' is set.

    Note: the timeout for the lambda HTTP request is quite long to accommodate AIPs that
    take substantial time to validate.  If there are connection issues it is recommended
    to use the 'ping' CLI command to ensure firewall access and authorization.
    """
    if not (aip_uuid or s3_uri):
        raise click.UsageError("You must provide either --aip-uuid/-a or --s3-uri/-u.")

    logger.debug("Starting AIP validation")

    # make request to AIP validator lambda
    try:
        result = validate_aip_via_lambda(
            aip_uuid=aip_uuid,
            aip_s3_uri=s3_uri,
            verbose=ctx.obj["VERBOSE"],
        )
    except requests.exceptions.RequestException as exc:
        error_msg = f"Error connecting to AIP validation lambda: {exc}"
        logger.error(error_msg)
        click.echo(error_msg, err=True)
        ctx.exit(1)
    except ValueError as exc:
        error_msg = f"Error with validation parameters: {exc}"
        logger.error(error_msg)
        click.echo(error_msg, err=True)
        ctx.exit(1)

    if elapsed := result.get("elapsed"):
        logger.debug(f"AIP validation elapsed: {elapsed}s")

    # send results to stdout and set exit codes
    if result.get("valid"):
        if details:
            click.echo(json.dumps(result))
        else:
            click.echo("OK")
        ctx.exit(0)
    else:
        click.echo(
            json.dumps(
                {
                    "error": result.get("error", "Unspecified"),
                    "error_details": result.get("error_details", None),
                }
            ),
            err=True,
        )
        ctx.exit(1)


@cli.command()
@click.pass_context
@click.option(
    "--input-csv-filepath",
    "-i",
    required=True,
    help="Filepath of CSV with AIP UUIDs or S3 URIs to be validated.",
)
@click.option(
    "--output-csv-filepath",
    "-o",
    required=True,
    help="Filepath of CSV for validation results.",
)
@click.option(
    "--max-workers",
    "-w",
    required=False,
    type=int,
    default=25,
    envvar="LAMBDA_MAX_CONCURRENCY",
    help=(
        "Maximum number of concurrent validation workers.  This should not exceed the "
        "maximum concurrency for the deployed AWS Lambda function."
    ),
)
def bulk_validate(
    ctx: click.Context,
    input_csv_filepath: str,
    output_csv_filepath: str,
    *,
    max_workers: int,
) -> None:
    """Bulk validate AIPs stored in S3 via the AIP UUID or S3 URI."""
    input_df = pd.read_csv(input_csv_filepath).replace({np.nan: None})

    if not {"aip_uuid", "aip_s3_uri"}.intersection(input_df.columns):
        error_msg = "Input CSV must have 'aip_uuid' and/or 'aip_s3_uri' columns."
        logger.error(error_msg)
        click.echo(error_msg, err=True)
        ctx.exit(1)

    # initialize results dataframe with input data
    results_df = input_df.copy()
    results_df["aip_s3_uri"] = None
    results_df["valid"] = False
    results_df["error"] = None
    results_df["error_details"] = None
    results_df["elapsed"] = None

    # init a thread lock ensuring only one thread writes to results_df at once
    results_lock = Lock()

    # invoke lambda in parallel via threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for row_idx, row in input_df.iterrows():
            futures[
                executor.submit(
                    validate_aip_bulk_worker,
                    row_idx,
                    row,
                    results_lock,
                    results_df,
                    verbose=ctx.obj["VERBOSE"],
                )
            ] = (row_idx, row)
            time.sleep(0.25)
        for completed, _future in enumerate(concurrent.futures.as_completed(futures)):
            logger.info(
                f"Progress: {completed + 1}/{len(futures)} AIPs processed "
                f"({(completed + 1) / len(futures) * 100:.1f}%)"
            )

    valid_count = results_df["valid"].sum()
    total_count = len(results_df)
    click.echo(f"Validation complete: {valid_count}/{total_count} AIPs valid")

    if output_csv_filepath:
        results_df.to_csv(output_csv_filepath, index=False)
        click.echo(f"Results saved to {output_csv_filepath}")


def validate_aip_via_lambda(
    aip_uuid: str | None = None,
    aip_s3_uri: str | None = None,
    *,
    verbose: bool = False,
) -> dict:
    """Validate a single AIP via the deployed AWS Lambda function.

    Args:
        aip_uuid: The UUID of the AIP to validate
        aip_s3_uri: The S3 URI of the AIP to validate
        verbose: Flag for verbose output
    """
    if not (aip_uuid or aip_s3_uri):
        error_msg = "Must provide either aip_uuid or aip_s3_uri"
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info(f"Validating AIP: {aip_uuid or aip_s3_uri}")

    response = requests.post(
        CONFIG.lambda_endpoint_url,
        json={
            "action": "validate",
            "challenge_secret": CONFIG.CHALLENGE_SECRET,
            "aip_uuid": aip_uuid,
            "aip_s3_uri": aip_s3_uri,
            "verbose": verbose,
        },
        timeout=900,  # 15 min timeout (AWS Lambda maximum) for large AIPs
    )

    if response.status_code != HTTPStatus.OK:
        logger.warning(f"Non 200 response from Lambda: {response.content.decode()}")

    try:
        result = response.json()
    except Exception:
        logger.error(
            "Error parsing JSON from Lambda response. "
            f"Raw response: {response.content.decode()[:480]}"  # limit output
        )
        raise

    status = "OK" if result.get("valid", False) else f"FAILED: {result.get('error')}"
    logger.info(f"AIP {aip_uuid or aip_s3_uri}, validation result: {status}")

    return result


def validate_aip_bulk_worker(
    row_idx: Any,  # noqa: ANN401
    row: pd.Series,
    results_lock: Lock,
    results_df: pd.DataFrame,
    *,
    verbose: bool = False,
) -> None:
    """Bulk worker function to validate a single AIP and update a results DataFrame."""
    aip_uuid = row.get("aip_uuid")
    s3_uri = row.get("aip_s3_uri")

    # ensure either AIP UUID or S3 URI present for row
    if not (aip_uuid or s3_uri):
        error_msg = "Row must have either aip_uuid or aip_s3_uri"
        logger.error(error_msg)
        with results_lock:
            results_df.loc[row_idx, "error"] = error_msg
        return

    # attempt validation and update a results dataframe
    try:
        result = validate_aip_via_lambda(
            aip_uuid=aip_uuid, aip_s3_uri=s3_uri, verbose=verbose
        )

        with results_lock:
            results_df.loc[row_idx] = {  # type: ignore[call-overload]
                "aip_s3_uri": result.get("s3_uri"),
                "valid": bool(result.get("valid", False)),
                "error": result.get("error"),
                "error_details": (
                    json.dumps(result.get("error_details"))
                    if result.get("error_details") is not None
                    else None
                ),
                "elapsed": result.get("elapsed"),
            }

    # catch any exceptions as a validation error
    except Exception as exc:  # noqa: BLE001
        error_msg = f"Error validating AIP {aip_uuid or s3_uri}: {exc}"
        logger.error(error_msg)
        with results_lock:
            results_df.loc[row_idx, "error"] = str(exc)


if __name__ == "__main__":
    cli()
