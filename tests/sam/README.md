# AWS Serverless Application Model (AWS SAM)

## Overview

This folder, `tests/sam`, provides an **experimental** approach to running an instance of the Lambda locally that responds to, and returns responses like, a deployed AWS Lambda behind a Function URL, Automatic Load Balancer (ALB), or a Gateway API (all of which can be thought of as "event sources" for invoking a Lambda).

This Lambda application is somewhat unique in that it also includes a CLI "sidecar" that is geared towards making HTTP requests to the deployed Lambda.  As such, for development and testing, having a local instance of the Lambda that accepts the same requests, and returns a true HTTP response, is quite helpful.

## SAM Installation

Ensure that AWS SAM CLI is installed: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html.

All following actions and commands should be performed from the root of the project (i.e. same directory as the `Dockerfile`).

## Building and Configuration

1- Create a JSON file for SAM that has environment variables for the container 

- copy `tests/sam/env.json.template` to `tests/sam/env.json` (which is git ignored)
- fill in missing sensitive env vars
  - ensure that `S3_INVENTORY_LOCATIONS` are for the AWS environment (e.g. dev, stage, prod) that you set in the terminal 

**NOTE:** AWS credentials are automatically passed from the terminal context that runs `make sam-run`; they do not need to be explicitly set as env vars.

2- Build Docker image:
```shell
make sam-build
```

## Running as HTTP endpoint

The following outlines how to run the Lambda SAM docker image as an HTTP endpoint, accepting requests and returning respnoses similar to a lambda behind an ALB, Function URL, or API Gateway.

1- Ensure AWS Dev `ArchivematicaManagers` credentials set in terminal and any other env vars in `tests/sam/env.json` up-to-date.
 
2- Run HTTP server:
```shell
make sam-run
```

This starts a server at `http://localhost:3000/s3-bagit-validator` (technically the suffix is arbitrary, but requires one). 

3- In another terminal, test with a curl command to this local lambda endpoint:
```shell
curl --location 'http://localhost:3000/s3-bagit-validator' \
--header 'Content-Type: application/json' \
--data '{
    "action":"ping",
    "challenge_secret":"totally-local-s3-bagit-validating",    
    "verbose":true
}'
```

Response should be a `200` in the form of:
```json
{
    "response": "pong",
    "inventory_query_test": [
        {
            "inventory_count": 97802
        }
    ]
}
```

## Additional SAM Functionality

The beauty of testing Lambdas with SAM is the ecosystem of things it can simulate.

For example, you can simulate what a payload from an Automatic Load Balancer (ALB) looks like when it's used to invoke a Lambda:

```shell
sam local generate-event alb request
```

Or, what an S3 `PUT` trigger event looks like:
```shell
sam local generate-event s3 put
```

You can also invoke the Lambda directly with a payload, e.g.:
```shell
echo {"message": "I am the payload"} | sam local invoke S3BagitValidatorFunction -e -
```

Much of this will depend on how the Lambda is configured (e.g. how it parses payloads), but lots of potential for interesting and _local_ testing here.