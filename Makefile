### This is the Terraform-generated header for s3-bagit-validator-dev. If   ###
###   this is a Lambda repo, uncomment the FUNCTION line below              ###
###   and review the other commented lines in the document.                 ###
ECR_NAME_DEV:=s3-bagit-validator-dev
ECR_URL_DEV:=222053980223.dkr.ecr.us-east-1.amazonaws.com/s3-bagit-validator-dev
ECR_URL_WEST_DEV:=222053980223.dkr.ecr.us-west-2.amazonaws.com/s3-bagit-validator-dev
FUNCTION_DEV:=s3-bagit-validator-dev
### End of Terraform-generated header                                       ###
SHELL=/bin/bash
DATETIME:=$(shell date -u +%Y%m%dT%H%M%SZ)


help: # Preview Makefile commands
	@awk 'BEGIN { FS = ":.*#"; print "Usage:  make <target>\n\nTargets:" } \
/^[-_[:alpha:]]+:.?*#/ { printf "  %-15s%s\n", $$1, $$2 }' $(MAKEFILE_LIST)

### Terraform-generated Developer Deploy Commands for Dev environment       ###
dist-dev: ## Build docker container (intended for developer-based manual build)
	docker build --platform linux/amd64 \
	    -t $(ECR_URL_DEV):latest \
	    -t $(ECR_URL_WEST_DEV):latest \
		-t $(ECR_URL_DEV):`git describe --always` \
		-t $(ECR_URL_WEST_DEV):`git describe --always` \
		-t $(ECR_NAME_DEV):latest .

publish-dev: dist-dev ## Build, tag and push (intended for developer-based manual publish)
	docker login -u AWS -p $$(aws ecr get-login-password --region us-east-1) $(ECR_URL_DEV)
	docker push $(ECR_URL_DEV):latest
	docker push $(ECR_URL_DEV):`git describe --always`
	docker login -u AWS -p $$(aws ecr get-login-password --region us-west-2) $(ECR_URL_WEST_DEV)
	docker push $(ECR_URL_WEST_DEV):latest
	docker push $(ECR_URL_WEST_DEV):`git describe --always`

### If this is a Lambda repo, uncomment the two lines below     ###
update-lambda-dev: ## Updates the lambda with whatever is the most recent image in the ecr (intended for developer-based manual update)
	aws lambda update-function-code --region us-east-1 --function-name $(FUNCTION_DEV) --image-uri $(ECR_URL_DEV):latest
	aws lambda update-function-code --region us-west-2 --function-name $(FUNCTION_DEV) --image-uri $(ECR_URL_WEST_DEV):latest


### Terraform-generated manual shortcuts for deploying to Stage. This       ###
###   requires that ECR_NAME_STAGE, ECR_URL_STAGE, and FUNCTION_STAGE       ###
###   environment variables are set locally by the developer and that the   ###
###   developer has authenticated to the correct AWS Account. The values    ###
###   for the environment variables can be found in the stage_build.yml     ###
###   caller workflow.                                                      ###
dist-stage: ## Only use in an emergency
	docker build --platform linux/amd64 \
	    -t $(ECR_URL_STAGE):latest \
		-t $(ECR_URL_STAGE):`git describe --always` \
		-t $(ECR_NAME_STAGE):latest .

publish-stage: ## Only use in an emergency
	docker login -u AWS -p $$(aws ecr get-login-password --region us-east-1) $(ECR_URL_STAGE)
	docker push $(ECR_URL_STAGE):latest
	docker push $(ECR_URL_STAGE):`git describe --always`

### If this is a Lambda repo, uncomment the two lines below                 ###
update-lambda-stage: ## Updates the lambda with whatever is the most recent image in the ecr (intended for developer-based manual update)
	aws lambda update-function-code --function-name $(FUNCTION_STAGE) --image-uri $(ECR_URL_STAGE):latest

#######################
# Dependency commands
#######################

install: # Install Python dependencies
	pipenv install --dev
	pipenv run pre-commit install

update: install # Update Python dependencies
	pipenv clean
	pipenv update --dev

######################
# Unit test commands
######################

test: # Run tests and print a coverage report
	pipenv run coverage run --source=lambdas -m pytest -vv -m "not integration"
	pipenv run coverage report -m

coveralls: test # Write coverage data to an LCOV report
	pipenv run coverage lcov -o ./coverage/lcov.info

test-integration:
	pipenv run pytest -vv -s -m "integration"

####################################
# Code quality and safety commands
####################################

lint: black mypy ruff safety # Run linters

black: # Run 'black' linter and print a preview of suggested changes
	pipenv run black --check --diff .

mypy: # Run 'mypy' linter
	pipenv run mypy .

ruff: # Run 'ruff' linter and print a preview of errors
	pipenv run ruff check .

safety: # Check for security vulnerabilities and verify Pipfile.lock is up-to-date
	pipenv run pip-audit
	pipenv verify

lint-apply: black-apply ruff-apply # Apply changes with 'black' and resolve 'fixable errors' with 'ruff'

black-apply: # Apply changes with 'black'
	pipenv run black .

ruff-apply: # Resolve 'fixable errors' with 'ruff'
	pipenv run ruff check --fix .


####################################
# SAM Lambda
####################################
sam-build: # Build SAM image for running Lambda locally
	sam build --template tests/sam/template.yaml

sam-run: # Run lambda locally as an HTTP server
	sam local start-api --template tests/sam/template.yaml --env-vars tests/sam/env.json