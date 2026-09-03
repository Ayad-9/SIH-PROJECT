"""
AWS Lambda Diagnostic & Production Bridge Handler
Guarantees execution without 502 Bad Gateway and captures any startup errors.
"""
import os
import sys
import json
import traceback

# Ensure current working directory is first in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

_handler = None
_init_error = None

try:
    from main import handler as _handler
except Exception as exc:
    _init_error = traceback.format_exc()


def lambda_handler(event, context):
    """Entrypoint for AWS Lambda default configuration."""
    global _handler, _init_error
    
    # If initialization failed, return diagnostic JSON with 200 OK so the browser can see the exact error
    if _init_error or _handler is None:
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*"
            },
            "body": json.dumps({
                "diagnostic_status": "MODULE_INITIALIZATION_ERROR",
                "python_version": sys.version,
                "current_directory": os.getcwd(),
                "sys_path": sys.path,
                "traceback": _init_error,
                "files_in_root": os.listdir(".") if os.path.exists(".") else []
            }, indent=2)
        }
    
    try:
        res = _handler(event, context)
        # Strip duplicate CORS headers to prevent browser "multiple Access-Control-Allow-Origin values '*, *'" error
        if isinstance(res, dict) and "headers" in res and isinstance(res["headers"], dict):
            cors_keys = [k for k in res["headers"].keys() if k.lower().startswith("access-control-")]
            for k in cors_keys:
                del res["headers"][k]
        return res
    except Exception as exc:
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*"
            },
            "body": json.dumps({
                "diagnostic_status": "INVOCATION_RUNTIME_ERROR",
                "exception": str(exc),
                "traceback": traceback.format_exc()
            }, indent=2)
        }


# Export alias so main.handler or lambda_function.handler also work
handler = lambda_handler
