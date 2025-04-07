FROM public.ecr.aws/lambda/python:3.12

# Copy function code
COPY . ${LAMBDA_TASK_ROOT}/

# Install dependencies
RUN pip3 install pipenv
RUN pipenv requirements > requirements.txt
RUN pip3 install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

# Set environment variables required by DuckDB
ENV HOME=/tmp
ENV TZ=UTC

CMD [ "lambdas.validator.lambda_handler" ]