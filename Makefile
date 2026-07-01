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

CPU_ARCH ?= $(shell cat .aws-architecture 2>/dev/null || echo "linux/amd64")

help: # Preview Makefile commands
	@awk 'BEGIN { FS = ":.*#"; print "Usage:  make <target>\n\nTargets:" } \
/^[-_[:alpha:]]+:.?*#/ { printf "  %-15s%s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ensure OS binaries aren't called if naming conflict with Make recipes
.PHONY: help install venv update test coveralls test-integration lint lint-fix security check-arch dist-dev publish-dev docker-clean dist-stage publish-stage update-lambda-dev update-lambda-stage sam-build sam-invoke sam-http-run sam-http-ping

##############################################
# Python Environment and Dependency commands
##############################################

install: .venv .git/hooks/pre-commit .git/hooks/pre-push # Install Python dependencies and create virtual environment if not exists
	uv sync --dev

.venv: # Creates virtual environment if not found
	@echo "Creating virtual environment at .venv..."
	uv venv .venv

.git/hooks/pre-commit: # Sets up pre-commit commit hooks if not setup
	@echo "Installing pre-commit commit hooks..."
	uv run pre-commit install --hook-type pre-commit

.git/hooks/pre-push: # Sets up pre-commit push hooks if not setup
	@echo "Installing pre-commit push hooks..."
	uv run pre-commit install --hook-type pre-push

venv: .venv # Create the Python virtual environment

update: # Update Python dependencies
	uv lock --upgrade
	uv sync --dev

######################
# Unit test commands
######################

test: # Run tests and print a coverage report
	uv run coverage run --source=lambdas -m pytest -vv -m "not integration"
	uv run coverage report -m

coveralls: test # Write coverage data to an LCOV report
	uv run coverage lcov -o ./coverage/lcov.info

test-integration: # Run integration tests
	uv run pytest -vv -s -m "integration"

####################################
# Code linting and formatting
####################################

lint: # Run linting, alerts only, no code changes
	uv run ruff format --diff
	uv run mypy .
	uv run ruff check .

lint-fix: # Run linting, auto fix behaviors where supported
	uv run ruff format .
	uv run ruff check --fix .

security: # Run security / vulnerability checks
	uv run pip-audit

####################################
# SAM Lambda
####################################

sam-build: # SAM: Build SAM image for running Lambda locally
	sam build --template tests/sam/template.yaml

sam-invoke: # SAM: Invoke lambda directly
	echo '{"msg":"in a bottle"}' \
		| sam local invoke -e -

sam-http-run: # SAM: Run lambda locally as an HTTP server
	sam local start-api --template tests/sam/template.yaml --env-vars tests/sam/env.json

sam-http-ping: # SAM: Send curl command to SAM HTTP server
	curl --location 'http://localhost:3000/s3-bagit-validator' \
		--header 'Content-Type: application/json' \
		--data '{"action":"ping","challenge_secret":"totally-local-s3-bagit-validating","verbose":true}'

###############################################
# Docker image, ECR, and Lambda Management
###############################################
check-arch:
	@ARCH_FILE=".aws-architecture"; \
	if [[ "$(CPU_ARCH)" != "linux/amd64" && "$(CPU_ARCH)" != "linux/arm64" ]]; then \
        echo "Invalid CPU_ARCH: $(CPU_ARCH)"; exit 1; \
    fi; \
	if [[ -f $$ARCH_FILE ]]; then \
		echo "latest-$(shell echo $(CPU_ARCH) | cut -d'/' -f2)" > .arch_tag; \
	else \
		echo "latest" > .arch_tag; \
	fi

dist-dev: check-arch # Build docker container (intended for developer-based manual build)
	@ARCH_TAG=$$(cat .arch_tag); \
	docker buildx inspect $(ECR_NAME_DEV) >/dev/null 2>&1 || docker buildx create --name $(ECR_NAME_DEV) --use; \
	docker buildx use $(ECR_NAME_DEV); \
	docker buildx build --platform $(CPU_ARCH) \
		--load \
		--tag $(ECR_URL_DEV):$$ARCH_TAG \
		--tag $(ECR_URL_DEV):make-$$ARCH_TAG \
		--tag $(ECR_URL_DEV):make-$(shell git describe --always) \
		--tag $(ECR_URL_WEST_DEV):$$ARCH_TAG \
		--tag $(ECR_URL_WEST_DEV):make-$$ARCH_TAG \
		--tag $(ECR_URL_WEST_DEV):make-$(shell git describe --always) \
		--tag $(ECR_NAME_DEV):$$ARCH_TAG \
		.

publish-dev: dist-dev # Build, tag and push (intended for developer-based manual publish)
	@ARCH_TAG=$$(cat .arch_tag); \
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(ECR_URL_DEV); \
	docker push $(ECR_URL_DEV):$$ARCH_TAG; \
	docker push $(ECR_URL_DEV):make-$$ARCH_TAG; \
	docker push $(ECR_URL_DEV):make-$(shell git describe --always); \
	aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $(ECR_URL_WEST_DEV); \
	docker push $(ECR_URL_WEST_DEV):$$ARCH_TAG; \
	docker push $(ECR_URL_WEST_DEV):make-$$ARCH_TAG; \
	docker push $(ECR_URL_WEST_DEV):make-$(shell git describe --always); \
	echo "Cleaning up dangling Docker images..."; \
	docker image prune -f --filter "dangling=true"

docker-clean: # Clean up Docker detritus
	@ARCH_TAG=$$(cat .arch_tag); \
	echo "Cleaning up Docker leftovers (containers, images, builders)"; \
	docker rmi -f $(ECR_URL_DEV):$$ARCH_TAG; \
	docker rmi -f $(ECR_URL_DEV):make-$$ARCH_TAG; \
	docker rmi -f $(ECR_URL_DEV):make-$(shell git describe --always) || true; \
	docker rmi -f $(ECR_URL_WEST_DEV):$$ARCH_TAG || true; \
	docker rmi -f $(ECR_URL_WEST_DEV):make-$$ARCH_TAG || true; \
	docker rmi -f $(ECR_NAME_DEV):$$ARCH_TAG || true; \
	docker buildx rm $(ECR_NAME_DEV) || true
	@rm -rf .arch_tag

update-lambda-dev: # Updates the lambda with whatever is the most recent image in the ecr (intended for developer-based manual update)
	aws lambda update-function-code --region us-east-1 --function-name $(FUNCTION_DEV) --image-uri $(ECR_URL_DEV):latest
	aws lambda update-function-code --region us-west-2 --function-name $(FUNCTION_DEV) --image-uri $(ECR_URL_WEST_DEV):latest

### Terraform-generated manual shortcuts for deploying to Stage. This       ###
###   requires that ECR_NAME_STAGE, ECR_URL_STAGE, and FUNCTION_STAGE       ###
###   environment variables are set locally by the developer and that the   ###
###   developer has authenticated to the correct AWS Account. The values    ###
###   for the environment variables can be found in the stage_build.yml     ###
###   caller workflow.                                                      ###
dist-stage: ## Only use in an emergency
	docker buildx build --platform $(CPU_ARCH) \
		--load \
		-t $(ECR_URL_STAGE):latest \
		-t $(ECR_URL_STAGE):`git describe --always` \
		-t $(ECR_NAME_STAGE):latest .

publish-stage: ## Only use in an emergency
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $(ECR_URL_STAGE)
	docker push $(ECR_URL_STAGE):latest
	docker push $(ECR_URL_STAGE):`git describe --always`

update-lambda-stage: ## Updates the lambda with whatever is the most recent image in the ecr (intended for developer-based manual update)
	aws lambda update-function-code --function-name $(FUNCTION_STAGE) --image-uri $(ECR_URL_STAGE):latest
