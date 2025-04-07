# s3-bagit-validator

AWS Lambda to validate a [Bagit](https://www.ietf.org/rfc/rfc8493.txt) bag stored in S3.

## Development

- To preview a list of available Makefile commands: `make help`
- To install with dev dependencies: `make install`
- To update dependencies: `make update`
- To run unit tests: `make test`
- To lint the repo: `make lint`

## Running Locally with Docker

<https://docs.aws.amazon.com/lambda/latest/dg/images-test.html>

- Build the container:

```bash
docker build -t validator:latest .
```

- Run the default handler for the container:

```bash
docker run --env-file .env -p 9000:8080 validator:latest
```

- Post to the container:

```bash
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{}'
```

- Observe output:

  ```
  "You have successfully called this lambda!"
  ```

## Running a Specific Handler Locally with Docker

If this repo contains multiple lambda functions, you can call any handler you copy into the container (see Dockerfile) by name as part of the `docker run` command:

```bash
docker run -p 9000:8080 validator:latest lambdas.<a-different-module>.lambda_handler
```

## Environment Variables

### Required

```shell
SENTRY_DSN=### If set to a valid Sentry DSN, enables Sentry exception monitoring. This is not needed for local development.
WORKSPACE=### Set to `dev` for local development, this will be set to `stage` and `prod` in those environments by Terraform.
CHALLENGE_SECRET=### Secret string that is passed as part of lambda invocation payload and checked before running
S3_INVENTORY_LOCATIONS=### Comma seperated list of S3 URIs that have S3 Inventory data for a particular bucket
```

### Optional

```shell
WARNING_ONLY_LOGGERS=### Optionally set "WARNING" logging level for comma seperated list of libraries; e.g. asyncio,botocore,urllib3,s3transfer,boto3
INTEGRATION_TEST_BUCKET=### [Integration tests] Bucket to use for integration testing
INTEGRATION_TEST_PREFIX=### [Integration tests] Prefix for any uploaded AIPs as part of integration testing
```

## Related Assets

* Infrastructure: TODO

```mermaid
mindmap
    root((s3-bagit-validator))        
```

## Maintainers

* Team: [DataEng](https://github.com/orgs/MITLibraries/teams/dataeng)
* Last Maintenance: 2025-03