FROM public.ecr.aws/lambda/python:3.13

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY pyproject.toml uv.lock* ./

RUN cd ${LAMBDA_TASK_ROOT} && \
    uv export --format requirements-txt --no-hashes --no-dev > requirements.txt && \
    uv pip install -r requirements.txt --target "${LAMBDA_TASK_ROOT}" --system

COPY . ${LAMBDA_TASK_ROOT}/

# Set environment variables required by DuckDB
ENV HOME=/tmp
ENV TZ=UTC

CMD ["lambdas.validator.lambda_handler"]