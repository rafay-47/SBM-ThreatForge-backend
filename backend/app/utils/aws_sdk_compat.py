"""Compatibility imports for AWS SDK modules in local development.

This module exposes boto3, ClientError, and Config.
If boto3/botocore are unavailable, it provides lightweight fallbacks that
allow modules to import successfully; actual AWS operations will still fail
with a clear ModuleNotFoundError when invoked.
"""

from __future__ import annotations

from typing import Any


class _MissingBoto3:
    def __getattr__(self, _name: str) -> Any:
        raise ModuleNotFoundError(
            "boto3 is required for AWS operations. Install backend app requirements "
            "or use the project virtual environment."
        )


try:
    import boto3 as _boto3  # type: ignore
except ModuleNotFoundError:
    boto3 = _MissingBoto3()
else:
    boto3 = _boto3


try:
    from botocore.config import Config  # type: ignore
except ModuleNotFoundError:

    class Config:  # type: ignore[override]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs


try:
    from botocore.exceptions import ClientError  # type: ignore
except ModuleNotFoundError:

    class ClientError(Exception):
        def __init__(self, error_response: dict | None = None, operation_name: str = ""):
            self.response = error_response or {
                "Error": {
                    "Code": "MissingAWSClient",
                    "Message": "boto3/botocore is not installed",
                }
            }
            self.operation_name = operation_name
            super().__init__(self.response["Error"]["Message"])
