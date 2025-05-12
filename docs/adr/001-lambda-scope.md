# 1. Lambda scope

Date: 2023-05-09

## Status

Accepted

## Context
With the addition of the `inventory` action to the `s3-bagit-validator` lambda, the lambda's scope is extending beyond what was originally envisioned. While the ability to export a CSV of S3 Inventory data is a convenience desired by stakeholders and using the lambda makes more sense than the sidecar CLI app, it is beginning to create a conceptual tension for the developers. This should represent the final extension of the lambda beyond its original scope of validating AIPs in S3. Any further extension requires a full reconsideration of the lambda and sidecar CLI app.

## Decision
No additional functionality should be added to this lambda unless it is related to AIP validation.

## Consequences
After the `inventory` action has been added to the lambda, any further functionality not explicitly related to AIP validation requires a reconsideration of the scope of this lambda and sidecar CLI app. The result of that reconsideration would likely be a significant shift for both the lambdas and sidecar CLI app, such as breaking them into multiple tightly-focused entities.