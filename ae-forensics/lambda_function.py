"""
AWS Lambda default entrypoint handler.
Exports lambda_handler to match default AWS Lambda configuration: lambda_function.lambda_handler
Also exports handler for custom configuration: main.handler / lambda_function.handler
"""
import os
import sys

# Ensure current directory is in sys.path for Lambda
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from main import handler, app

def lambda_handler(event, context):
    """Bridge for default AWS Lambda handler setting: lambda_function.lambda_handler"""
    return handler(event, context)
