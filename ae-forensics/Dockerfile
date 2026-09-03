FROM public.ecr.aws/lambda/python:3.11

# Set task root
WORKDIR ${LAMBDA_TASK_ROOT}

# Install build dependencies if needed
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY main.py database.py ${LAMBDA_TASK_ROOT}/
COPY core/ ${LAMBDA_TASK_ROOT}/core/
COPY services/ ${LAMBDA_TASK_ROOT}/services/
COPY templates/ ${LAMBDA_TASK_ROOT}/templates/

# Set AWS Lambda handler (Mangum adapter in main.py)
CMD ["main.handler"]
