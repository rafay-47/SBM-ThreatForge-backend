"""
Utility functions for handling database operations, and AI model interactions.
Provides functionality for state management, image processing, and error handling.
Includes tools for working with AI models and structured data.
"""

import base64
import copy
import decimal
import os
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, ParamSpec, TypeVar, Union

import structlog
try:
    from botocore.exceptions import ClientError
except ImportError:
    ClientError = Exception
from constants import (
    AWS_SERVICE_DYNAMODB,
    AWS_SERVICE_S3,
    DB_FIELD_ASSETS,
    DB_FIELD_FLOWS,
    DB_FIELD_GAPS,
    DB_FIELD_SPACE_CONTEXT,
    DB_FIELD_ID,
    DB_FIELD_JOB_ID,
    DB_FIELD_RETRY,
    DB_FIELD_STATE,
    DB_FIELD_THREATS,
    DB_FIELD_TIMESTAMP,
    DEFAULT_REGION,
    ENV_AGENT_TRAIL_TABLE,
    ENV_AWS_REGION,
    ENV_JOB_STATUS_TABLE,
    ERROR_DYNAMODB_OPERATION_FAILED,
    ERROR_MISSING_ENV_VAR,
    ERROR_S3_OPERATION_FAILED,
    FLUSH_MODE_REPLACE,
)
from exceptions import DynamoDBError, S3Error, ThreatModelingError
try:
    from langchain_aws import ChatBedrockConverse
except ImportError:
    ChatBedrockConverse = Any
from langchain_core.messages import BaseMessage, SystemMessage
from langchain_core.messages.human import HumanMessage
from langchain_core.runnables.config import RunnableConfig
from monitoring import operation_context, with_error_context
from prompt_provider import structure_prompt
from state import AgentState
from langgraph.types import Overwrite

logger = structlog.get_logger()

# Environment variable lookups using centralized constants
JOB_STATUS_TABLE = os.environ.get(ENV_JOB_STATUS_TABLE)
TRAIL_TABLE = os.environ.get(ENV_AGENT_TRAIL_TABLE)
REGION = os.environ.get(ENV_AWS_REGION, DEFAULT_REGION)
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "local").lower()

# Shared database access (lazy-initialized)
_db_access = None
_storage_access = None


def _get_db_access():
    """Return database access via factory (Supabase or DynamoDB)."""
    global _db_access
    if _db_access is None:
        if DEPLOYMENT_MODE == "aws":
            import boto3
            _db_access = boto3.resource(AWS_SERVICE_DYNAMODB, region_name=REGION)
        else:
            _db_access = _SupabaseDBAccess()
    return _db_access


def _get_storage_access():
    """Return storage access via factory (Supabase or S3)."""
    global _storage_access
    if _storage_access is None:
        if DEPLOYMENT_MODE == "aws":
            import boto3
            _storage_access = boto3.client(AWS_SERVICE_S3, region_name=REGION)
        else:
            _storage_access = _SupabaseStorageAccess()
    return _storage_access


class _SupabaseDBTable:
    """Minimal table-like wrapper for Supabase REST API."""
    def __init__(self, url, key, table_name):
        self._url = url.rstrip("/")
        self._key = key
        self._table = table_name

    def get_item(self, Key):
        import json
        from urllib import request, error
        pk = list(Key.keys())[0]
        pv = Key[pk]
        url = f"{self._url}/rest/v1/{self._table}?{pk}=eq.{pv}"
        req = request.Request(url, headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"})
        try:
            with request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode())
                return {"Item": rows[0]} if rows else {}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase GET failed [{e.code}]: {e.read().decode()}")

    def put_item(self, Item):
        import json
        from urllib import request, error
        url = f"{self._url}/rest/v1/{self._table}"
        data = json.dumps(Item).encode()
        req = request.Request(url, data=data, method="POST", headers={
            "apikey": self._key, "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            # Match DynamoDB PutItem: insert or replace on primary key conflict
            "Prefer": "return=minimal,resolution=merge-duplicates",
        })
        try:
            with request.urlopen(req, timeout=30) as resp:
                return {"ResponseMetadata": {"HTTPStatusCode": resp.status}}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase PUT failed [{e.code}]: {e.read().decode()}")

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues, ReturnValues=None):
        import json
        from urllib import request, error
        pk = list(Key.keys())[0]
        pv = Key[pk]
        url = f"{self._url}/rest/v1/{self._table}?{pk}=eq.{pv}"
        # Parse SET expressions
        set_match = UpdateExpression.strip().split("SET ", 1)
        payload = {}
        if len(set_match) > 1:
            clauses = [c.strip() for c in set_match[1].split(",")]
            for clause in clauses:
                parts = clause.split("=")
                col = parts[0].strip().lstrip("#")
                val_key = parts[1].strip().lstrip(":")
                col_name = ExpressionAttributeNames.get(f"#{col}", col)
                payload[col_name] = ExpressionAttributeValues.get(f":{val_key}")
        data = json.dumps(payload).encode()
        req = request.Request(url, data=data, method="PATCH", headers={
            "apikey": self._key, "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json", "Prefer": "return=representation",
        })
        try:
            with request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode())
                return {"Attributes": rows[0] if rows else {}}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase UPDATE failed [{e.code}]: {e.read().decode()}")

    def delete_item(self, Key):
        from urllib import request, error
        pk = list(Key.keys())[0]
        pv = Key[pk]
        url = f"{self._url}/rest/v1/{self._table}?{pk}=eq.{pv}"
        req = request.Request(url, method="DELETE", headers={
            "apikey": self._key, "Authorization": f"Bearer {self._key}",
            "Prefer": "return=minimal",
        })
        try:
            with request.urlopen(req, timeout=30) as resp:
                return {"ResponseMetadata": {"HTTPStatusCode": resp.status}}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase DELETE failed [{e.code}]: {e.read().decode()}")

    def query(self, KeyConditionExpression, ExpressionAttributeValues=None, IndexName=None, **kwargs):
        import json
        from urllib import request, error
        # Parse "col = :val" expression
        parts = KeyConditionExpression.split("=")
        col = parts[0].strip()
        val_key = parts[1].strip().lstrip(":")
        val = (ExpressionAttributeValues or {}).get(f":{val_key}")
        url = f"{self._url}/rest/v1/{self._table}?{col}=eq.{val}"
        req = request.Request(url, headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"})
        try:
            with request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode())
                return {"Items": rows, "Count": len(rows)}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase QUERY failed [{e.code}]: {e.read().decode()}")

    def scan(self, FilterExpression=None, ExpressionAttributeNames=None, ExpressionAttributeValues=None, Limit=None, **kwargs):
        import json
        from urllib import request, error
        url = f"{self._url}/rest/v1/{self._table}"
        if FilterExpression and ExpressionAttributeNames and ExpressionAttributeValues:
            # Parse "#col = :val"
            parts = FilterExpression.split("=")
            col_raw = parts[0].strip().lstrip("#")
            val_key = parts[1].strip().lstrip(":")
            col = ExpressionAttributeNames.get(f"#{col_raw}", col_raw)
            val = ExpressionAttributeValues.get(f":{val_key}")
            url = f"{url}?{col}=eq.{val}"
        req = request.Request(url, headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"})
        try:
            with request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode())
                return {"Items": rows, "Count": len(rows)}
        except error.HTTPError as e:
            raise DynamoDBError(f"Supabase SCAN failed [{e.code}]: {e.read().decode()}")


class _SupabaseDBAccess:
    """Minimal Supabase database access with DynamoDB-like interface."""
    def __init__(self):
        self._url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        self._key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

    def Table(self, name):
        return _SupabaseDBTable(self._url, self._key, name)

    def table(self, name):
        return _SupabaseDBTable(self._url, self._key, name)


class _SupabaseStorageAccess:
    """Minimal Supabase storage access with S3-like interface."""
    def __init__(self):
        self._url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        self._key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

    def get_object(self, bucket, key):
        import json
        from urllib import request, error
        url = f"{self._url}/storage/v1/object/{bucket}/{key}"
        req = request.Request(url, headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"})
        try:
            with request.urlopen(req, timeout=30) as resp:
                return resp.read()
        except error.HTTPError as e:
            raise S3Error(f"Supabase storage GET failed [{e.code}]: {e.read().decode()}")

    def put_object(self, bucket, key, data, content_type="application/octet-stream"):
        import json
        from urllib import request, error
        url = f"{self._url}/storage/v1/object/{bucket}/{key}"
        req = request.Request(url, data=data, method="POST", headers={
            "apikey": self._key, "Authorization": f"Bearer {self._key}",
            "Content-Type": content_type,
        })
        try:
            with request.urlopen(req, timeout=30) as resp:
                return {"ResponseMetadata": {"HTTPStatusCode": resp.status, "Key": key}}
        except error.HTTPError as e:
            raise S3Error(f"Supabase storage PUT failed [{e.code}]: {e.read().decode()}")

    def generate_presigned_put_object(self, bucket_name, object_key, file_type, expiration):
        import json
        from urllib import request, error
        url = f"{self._url}/storage/v1/object/upload/sign/{bucket_name}/{object_key}"
        data = json.dumps({"expiresIn": int(expiration)}).encode()
        req = request.Request(url, data=data, method="POST", headers={
            "apikey": self._key, "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
        })
        try:
            with request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode())
                signed_url = payload.get("signedURL") or payload.get("signedUrl") or payload.get("url", "")
                token = payload.get("token")
                if token and "token=" not in signed_url:
                    sep = "&" if "?" in signed_url else "?"
                    signed_url = f"{signed_url}{sep}token={token}"
                if not signed_url.startswith("http"):
                    signed_url = f"{self._url}/{signed_url.lstrip('/')}"
                # Supabase may return /object/sign/... without /storage/v1 (browser GET would 404 + CORS noise)
                if "/storage/v1/" not in signed_url and "/object/" in signed_url:
                    signed_url = signed_url.replace("/object/", "/storage/v1/object/", 1)
                return signed_url
        except error.HTTPError as e:
            raise S3Error(f"Supabase presign failed [{e.code}]: {e.read().decode()}")


def unwrap_overwrite(value: Any, default: Any = None) -> Any:
    """Unwrap LangGraph Overwrite objects to get the actual value.

    Args:
        value: Any value that might be wrapped in Overwrite
        default: Fallback if value is None

    Returns:
        The unwrapped value, the original value, or default if None.
    """
    if isinstance(value, Overwrite):
        return value.value
    if value is None:
        return default
    return value


# Environment variable lookups using centralized constants
JOB_STATUS_TABLE = os.environ.get(ENV_JOB_STATUS_TABLE)
TRAIL_TABLE = os.environ.get(ENV_AGENT_TRAIL_TABLE)
REGION = os.environ.get(ENV_AWS_REGION, DEFAULT_REGION)

# Type definitions
P = ParamSpec("P")
R = TypeVar("R")

# ============================================================================
# DATA CONVERSION UTILITIES
# ============================================================================


def convert_decimals(
    obj: Union[List[Any], Dict[Any, Any], decimal.Decimal, Any],
) -> Union[List[Any], Dict[Any, Any], int, float, Any]:
    """
    Recursively converts Decimal to float or int in a dictionary.

    Args:
        obj: Object that may contain Decimal values to convert.

    Returns:
        Object with Decimal values converted to int/float.
    """
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, decimal.Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    else:
        return obj


# ============================================================================
# DYNAMODB OPERATIONS
# ============================================================================


@with_error_context("update job state")
def update_job_state(
    job_id: str,
    state: AgentState,
    retry: Optional[bool] = None,
    detail: Optional[str] = None,
    job_context_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Update job state in DynamoDB with proper error handling and logging.

    Args:
        job_id: Unique identifier for the job.
        state: New state to set for the job.
        retry: Optional retry flag to set.
        detail: Optional detail message for the current state (e.g., "Thinking", "Reviewing catalog").
        job_context_id: Optional job context for operation tracking.

    Returns:
        DynamoDB response or None if operation failed.

    Raises:
        DynamoDBError: If update operation fails.
    """
    if not JOB_STATUS_TABLE:
        raise DynamoDBError(f"{ENV_JOB_STATUS_TABLE} {ERROR_MISSING_ENV_VAR}")

    context_id = job_context_id or f"update-job-{job_id}"

    with operation_context("update_job_state", context_id):
        try:
            db = _get_db_access()
            if DEPLOYMENT_MODE == "aws":
                table = db.Table(JOB_STATUS_TABLE)
                current_item = table.get_item(Key={DB_FIELD_ID: job_id})
                if current_item.get("Item", {}).get("cancelled"):
                    logger.debug(
                        "Skipping state update - session was cancelled, resetting flag",
                        job_id=job_id,
                        requested_state=state,
                    )
                    table.update_item(
                        Key={DB_FIELD_ID: job_id},
                        UpdateExpression="REMOVE #cancelled",
                        ExpressionAttributeNames={"#cancelled": "cancelled"},
                    )
                    return None
            else:
                table = db.table(JOB_STATUS_TABLE)
                current_item = table.get_item(Key={DB_FIELD_ID: job_id})
                if current_item.get("Item", {}).get("cancelled"):
                    logger.debug(
                        "Skipping state update - session was cancelled, resetting flag",
                        job_id=job_id,
                        requested_state=state,
                    )
                    table.delete_item(Key={DB_FIELD_ID: job_id})
                    return None

            logger.debug(
                "Updating job state",
                job_id=job_id,
                new_state=state,
                retry=retry,
                table=JOB_STATUS_TABLE,
            )

            current_utc = datetime.now(timezone.utc).isoformat()

            # Build update expression and attributes
            update_expr = f"SET #{DB_FIELD_STATE} = :{DB_FIELD_STATE}, #{DB_FIELD_TIMESTAMP} = :{DB_FIELD_TIMESTAMP}"
            expr_names = {
                f"#{DB_FIELD_STATE}": DB_FIELD_STATE,
                f"#{DB_FIELD_TIMESTAMP}": DB_FIELD_TIMESTAMP,
            }
            expr_values = {
                f":{DB_FIELD_STATE}": state,
                f":{DB_FIELD_TIMESTAMP}": current_utc,
            }

            # Add retry if provided
            if retry is not None:
                update_expr += f", #{DB_FIELD_RETRY} = :{DB_FIELD_RETRY}"
                expr_names[f"#{DB_FIELD_RETRY}"] = DB_FIELD_RETRY
                expr_values[f":{DB_FIELD_RETRY}"] = retry

            # Add detail if provided, or remove stale detail
            if detail is not None:
                update_expr += ", #detail = :detail"
                expr_names["#detail"] = "detail"
                expr_values[":detail"] = detail
            else:
                update_expr += " REMOVE #detail"
                expr_names["#detail"] = "detail"

            if DEPLOYMENT_MODE == "aws":
                response = table.update_item(
                    Key={DB_FIELD_ID: job_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues=expr_values,
                    ReturnValues="UPDATED_NEW",
                )
            else:
                table.update_item(
                    Key={DB_FIELD_ID: job_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues=expr_values,
                )
                response = table.get_item(Key={DB_FIELD_ID: job_id})

            logger.debug(
                "Job state updated successfully",
                job_id=job_id,
                state=state,
                updated_attributes=response.get("Attributes", {}),
            )

            return response

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(
                "Database client error during job state update",
                job_id=job_id,
                error_code=error_code,
                error_message=error_message,
                table=JOB_STATUS_TABLE,
            )
            raise DynamoDBError(f"{ERROR_DYNAMODB_OPERATION_FAILED}: {error_message}")

        except Exception as e:
            logger.error(
                "Unexpected error during job state update",
                job_id=job_id,
                error=str(e),
                table=JOB_STATUS_TABLE,
            )
            raise


@with_error_context("update trail")
def update_trail(
    job_id: str,
    assets: Optional[str] = None,
    flows: Optional[str] = None,
    threats: Optional[Union[str, List[str]]] = None,
    gaps: Optional[Union[str, List[str]]] = None,
    space_context: Optional[str] = None,
    flush: int = 0,
    job_context_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Update trail information in DynamoDB with comprehensive logging.

    Args:
        job_id: Unique identifier for the job.
        assets: Assets information to update.
        flows: Flows information to update.
        threats: Threats information to update (string or list).
        gaps: Gaps information to update (string or list).
        flush: Whether to flush existing list data (0=replace, 1=append).
        job_context_id: Optional job context for operation tracking.

    Returns:
        DynamoDB response or None if no updates needed.

    Raises:
        DynamoDBError: If update operation fails.
    """
    if not TRAIL_TABLE:
        raise DynamoDBError(f"{ENV_AGENT_TRAIL_TABLE} {ERROR_MISSING_ENV_VAR}")

    context_id = job_context_id or f"update-trail-{job_id}"

    with operation_context("update_trail", context_id):
        logger.debug(
            "Starting trail update",
            job_id=job_id,
            has_assets=assets is not None,
            has_flows=flows is not None,
            has_threats=threats is not None,
            has_gaps=gaps is not None,
            flush_mode=flush,
            table=TRAIL_TABLE,
        )

        try:
            db = _get_db_access()
            if DEPLOYMENT_MODE == "aws":
                table = db.Table(TRAIL_TABLE)
            else:
                table = db.table(TRAIL_TABLE)

            # Build update expression
            update_expr = "SET "
            expr_names = {}
            expr_values = {}
            is_first = True

            # Handle string fields
            for field_name, field_value, db_field in [
                ("assets", assets, DB_FIELD_ASSETS),
                ("flows", flows, DB_FIELD_FLOWS),
                ("space_context", space_context, DB_FIELD_SPACE_CONTEXT),
            ]:
                if field_value is not None:
                    if not is_first:
                        update_expr += ", "
                    update_expr += f"#{db_field} = :{db_field}"
                    expr_names[f"#{db_field}"] = db_field
                    expr_values[f":{db_field}"] = field_value
                    is_first = False

            # Handle list fields
            for field_name, field_value, db_field in [
                ("threats", threats, DB_FIELD_THREATS),
                ("gaps", gaps, DB_FIELD_GAPS),
            ]:
                if field_value is not None:
                    field_list = (
                        field_value if isinstance(field_value, list) else [field_value]
                    )

                    if not is_first:
                        update_expr += ", "

                    if flush == FLUSH_MODE_REPLACE:
                        update_expr += f"#{db_field} = :{db_field}"
                        expr_values[f":{db_field}"] = field_list
                    else:
                        # Atomic append-or-create using if_not_exists
                        update_expr += f"#{db_field} = list_append(if_not_exists(#{db_field}, :empty_{db_field}), :{db_field})"
                        expr_values[f":empty_{db_field}"] = []
                        expr_values[f":{db_field}"] = field_list

                    expr_names[f"#{db_field}"] = db_field
                    is_first = False

            # Only proceed if there's something to update
            if is_first:
                logger.debug("No fields to update in trail", job_id=job_id)
                return None

            if DEPLOYMENT_MODE == "aws":
                response = table.update_item(
                    Key={DB_FIELD_ID: job_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues=expr_values,
                    ReturnValues="UPDATED_NEW",
                )
            else:
                table.update_item(
                    Key={DB_FIELD_ID: job_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues=expr_values,
                )
                response = table.get_item(Key={DB_FIELD_ID: job_id})

            updated_fields = list(expr_names.values())
            logger.debug(
                "Trail updated successfully",
                job_id=job_id,
                updated_fields=updated_fields,
                flush_mode=flush,
            )

            return response

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(
                "Database client error during trail update",
                job_id=job_id,
                error_code=error_code,
                error_message=error_message,
                table=TRAIL_TABLE,
            )
            raise DynamoDBError(f"{ERROR_DYNAMODB_OPERATION_FAILED}: {error_message}")

        except Exception as e:
            logger.error(
                "Unexpected error during trail update",
                job_id=job_id,
                error=str(e),
                table=TRAIL_TABLE,
            )
            raise


@with_error_context("create DynamoDB item")
def create_dynamodb_item(
    agent_state: AgentState, table_name: str, job_context_id: Optional[str] = None
) -> None:
    """
    Create a new DynamoDB item from agent state.

    Args:
        agent_state: Agent state containing all job information.
        table_name: DynamoDB table name to insert into.
        job_context_id: Optional job context for operation tracking.

    Raises:
        DynamoDBError: If item creation fails.
    """
    context_id = job_context_id or f"create-item-{agent_state.get('job_id', 'unknown')}"

    with operation_context("create_dynamodb_item", context_id):
        try:
            job_id = agent_state.get("job_id")
            if not job_id:
                raise ValueError("job_id is required in agent_state")

            logger.debug("Creating database item", job_id=job_id, table=table_name)

            db = _get_db_access()
            if DEPLOYMENT_MODE == "aws":
                table = db.Table(table_name)
            else:
                table = db.table(table_name)

            current_utc = datetime.now(timezone.utc).isoformat()

            # Unwrap any Overwrite objects from state
            threat_list = unwrap_overwrite(agent_state["threat_list"])
            assets = unwrap_overwrite(agent_state["assets"])
            system_architecture = unwrap_overwrite(agent_state["system_architecture"])

            # Convert agent state to DynamoDB item
            item = {
                DB_FIELD_JOB_ID: job_id,
                "summary": agent_state.get("summary"),
                "assets": assets.dict() if hasattr(assets, "dict") else assets,
                "system_architecture": system_architecture.dict()
                if hasattr(system_architecture, "dict")
                else system_architecture,
                "threat_list": threat_list.dict()
                if hasattr(threat_list, "dict")
                else threat_list,
                "description": agent_state.get("description"),
                "assumptions": agent_state.get("assumptions"),
                "s3_location": agent_state["s3_location"],
                "image_type": agent_state.get("image_type"),
                "title": agent_state.get("title"),
                "owner": agent_state.get("owner"),
                "retry": agent_state.get("retry"),
                "timestamp": current_utc,
                "application_type": agent_state.get("application_type"),
                "token_usage": agent_state.get("token_usage"),
                "space_insights": (
                    unwrap_overwrite(agent_state.get("space_insights")).dict()
                    if agent_state.get("space_insights")
                    else None
                ),
                "parent_id": agent_state.get("parent_id"),
                "space_id": agent_state.get("space_id"),
            }

            # Remove None values to avoid DynamoDB issues
            item = {k: v for k, v in item.items() if v is not None}

            if DEPLOYMENT_MODE == "aws":
                table.put_item(Item=item)
            else:
                table.put_item(Item=item)

            logger.debug(
                "Database item created successfully",
                job_id=job_id,
                table=table_name,
                item_keys=list(item.keys()),
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(
                "Database client error during item creation",
                job_id=agent_state.get("job_id"),
                error_code=error_code,
                error_message=error_message,
                table=table_name,
            )
            raise DynamoDBError(f"{ERROR_DYNAMODB_OPERATION_FAILED}: {error_message}")

        except Exception as e:
            logger.error(
                "Unexpected error during item creation",
                job_id=agent_state.get("job_id"),
                error=str(e),
                table=table_name,
                stack_trace=traceback.format_exc(),
            )
            raise


@with_error_context("update item with backup")
def update_item_with_backup(
    job_id: str,
    table_name: str,
    backup_table_name: str,
    job_context_id: Optional[str] = None,
) -> None:
    """
    Store a backup of the DynamoDB item in a dedicated backup table.

    Storing the backup in a separate table avoids exceeding the 400 KB DynamoDB
    item size limit on large threat models.

    Args:
        job_id: The primary key of the item to back up.
        table_name: The source DynamoDB table name.
        backup_table_name: The dedicated backup DynamoDB table name.
        job_context_id: Optional job context for operation tracking.

    Raises:
        DynamoDBError: If backup operation fails.
    """
    context_id = job_context_id or f"backup-{job_id}"

    with operation_context("update_item_with_backup", context_id):
        try:
            logger.debug(
                "Creating backup for database item", job_id=job_id, table=table_name
            )

            db = _get_db_access()
            if DEPLOYMENT_MODE == "aws":
                source_table = db.Table(table_name)
                backup_table = db.Table(backup_table_name)
                response = source_table.get_item(Key={DB_FIELD_JOB_ID: job_id})
            else:
                source_table = db.table(table_name)
                backup_table = db.table(backup_table_name)
                response = source_table.get_item(Key={DB_FIELD_JOB_ID: job_id})

            if "Item" not in response:
                logger.warning(
                    "Item not found for backup", job_id=job_id, table=table_name
                )
                raise DynamoDBError(
                    f"Item with job_id {job_id} not found in table {table_name}"
                )

            backup_data = copy.deepcopy(response["Item"])

            if DEPLOYMENT_MODE == "aws":
                backup_table.put_item(Item=backup_data)
            else:
                backup_table.put_item(Item=backup_data)

            logger.debug(
                "Item backup created successfully",
                job_id=job_id,
                backup_table=backup_table_name,
                backup_keys=list(backup_data.keys()),
            )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(
                "Database client error during backup",
                job_id=job_id,
                error_code=error_code,
                error_message=error_message,
                table=table_name,
            )
            raise DynamoDBError(f"{ERROR_DYNAMODB_OPERATION_FAILED}: {error_message}")

        except Exception as e:
            logger.error(
                "Unexpected error during backup creation",
                job_id=job_id,
                error=str(e),
                table=table_name,
                stack_trace=traceback.format_exc(),
            )
            raise


@with_error_context("fetch results")
def fetch_results(job_id: str, table_name: str) -> Dict[str, Any]:
    """
    Fetch results from DynamoDB with proper error handling.

    Args:
        job_id: The job ID to fetch results for.
        table_name: The DynamoDB table name.

    Returns:
        Dictionary containing job results or status.

    Raises:
        DynamoDBError: If fetch operation fails.
    """
    try:
        logger.debug("Fetching job results", job_id=job_id, table=table_name)

        db = _get_db_access()
        if DEPLOYMENT_MODE == "aws":
            table = db.Table(table_name)
            response = table.get_item(Key={DB_FIELD_JOB_ID: job_id})
        else:
            table = db.table(table_name)
            response = table.get_item(Key={DB_FIELD_JOB_ID: job_id})

        if "Item" in response:
            logger.debug("Job results found", job_id=job_id, table=table_name)
            return {
                "job_id": job_id,
                "state": "Found",
                "item": convert_decimals(response["Item"]),
            }
        else:
            logger.warning("Job results not found", job_id=job_id, table=table_name)
            return {"job_id": job_id, "state": "Not Found", "item": None}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(
            "Database client error during fetch",
            job_id=job_id,
            error_code=error_code,
            error_message=error_message,
            table=table_name,
        )
        raise DynamoDBError(f"{ERROR_DYNAMODB_OPERATION_FAILED}: {error_message}")

    except Exception as e:
        logger.error(
            "Unexpected error during fetch",
            job_id=job_id,
            error=str(e),
            table=table_name,
        )
        raise


# ============================================================================
# S3 OPERATIONS
# ============================================================================


@with_error_context("parse S3 image to base64")
def parse_s3_image_to_base64(bucket_name: str, object_key: str) -> Optional[str]:
    """
    Download image from S3 and convert to base64.

    Args:
        bucket_name: S3 bucket name.
        object_key: S3 object key.

    Returns:
        Base64 encoded image string or None if operation failed.

    Raises:
        S3Error: If S3 operation fails.
    """
    try:
        logger.debug(
            "Converting storage image to base64", bucket=bucket_name, key=object_key
        )

        storage = _get_storage_access()

        if DEPLOYMENT_MODE == "aws":
            response = storage.get_object(Bucket=bucket_name, Key=object_key)
            image_content = response["Body"].read()
        else:
            image_content = storage.get_object(bucket_name, object_key)

        base64_encoded = base64.b64encode(image_content).decode("utf-8")

        logger.debug(
            "S3 image converted to base64 successfully",
            bucket=bucket_name,
            key=object_key,
            encoded_size=len(base64_encoded),
        )

        return base64_encoded

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]

        if DEPLOYMENT_MODE == "aws":
            if error_code == "NoSuchKey":
                logger.error(
                    "Storage object not found",
                    bucket=bucket_name,
                    key=object_key,
                    error_code=error_code,
                )
                raise S3Error(
                    f"The object {object_key} does not exist in bucket {bucket_name}"
                )
            elif error_code == "NoSuchBucket":
                logger.error(
                    "Storage bucket not found", bucket=bucket_name, error_code=error_code
                )
                raise S3Error(f"The bucket {bucket_name} does not exist")
            else:
                logger.error(
                    "Storage client error",
                    bucket=bucket_name,
                    key=object_key,
                    error_code=error_code,
                    error_message=error_message,
                )
                raise S3Error(f"{ERROR_S3_OPERATION_FAILED}: {error_message}")
        else:
            logger.error(
                "Storage operation failed",
                bucket=bucket_name,
                key=object_key,
                error=str(e),
            )
            raise S3Error(f"{ERROR_S3_OPERATION_FAILED}: {error_message}")

    except Exception as e:
        logger.error(
            "Unexpected error during S3 operation",
            bucket=bucket_name,
            key=object_key,
            error=str(e),
        )
        raise


# ============================================================================
# AI MODEL UTILITIES
# ============================================================================


def flatten_ai_message_content(message: BaseMessage) -> str:
    """Normalize assistant message content to plain text (OpenAI / OpenRouter / Bedrock)."""
    raw = getattr(message, "content", None)
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        parts: List[str] = []
        for block in raw:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(block.get("text", ""))
        return "\n".join(parts)
    return str(raw)


def _retry_with_structure(
    model: ChatBedrockConverse,
    response: BaseMessage,
    struct: ChatBedrockConverse,
    runnable_config: Optional[RunnableConfig] = None,
) -> BaseMessage:
    """
    Retry AI model response with structured output.

    Args:
        model: Main AI model instance.
        response: Original response to restructure.
        struct: Structured output model.

    Returns:
        Structured response message.
    """
    try:
        logger.debug("Retrying with structured output")

        human_structure = HumanMessage(
            content=[
                {
                    "type": "text",
                    "text": "Convert the <response> into a structured output",
                },
            ]
        )

        text = flatten_ai_message_content(response)
        struct_message = [
            SystemMessage(content=structure_prompt(text)),
            human_structure,
        ]
        model_with_tools = model.with_structured_output(struct)

        if runnable_config is not None:
            result = model_with_tools.invoke(struct_message, runnable_config)
        else:
            result = model_with_tools.invoke(struct_message)

        logger.debug("Structured output retry successful")
        return result

    except Exception as e:
        logger.error("Error during structured output retry", error=str(e))
        raise


def handle_asset_error(
    model: ChatBedrockConverse,
    struct: ChatBedrockConverse,
    thinking: bool = True,
    runnable_config: Optional[RunnableConfig] = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to handle asset processing errors with optional retry logic.

    Args:
        model: Main AI model instance.
        struct: Structured output model.
        thinking: Whether to retry with structured output on error.
        runnable_config: LangGraph RunnableConfig for callback propagation (token usage, etc.).

    Returns:
        Decorator function for error handling.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        def wrapper(response: BaseMessage, *args: P.args, **kwargs: P.kwargs) -> R:
            try:
                logger.debug("Processing asset response", function=func.__name__)
                result = func(response, *args, **kwargs)
                logger.debug("Asset processing successful", function=func.__name__)
                return result

            except Exception as e:
                logger.error(
                    "Asset processing error",
                    function=func.__name__,
                    error=str(e),
                    thinking_enabled=thinking,
                )

                if thinking:
                    logger.debug(
                        "Attempting structured output retry", function=func.__name__
                    )
                    try:
                        return _retry_with_structure(
                            model, response, struct, runnable_config
                        )
                    except Exception as retry_error:
                        logger.error(
                            "Structured output retry failed",
                            function=func.__name__,
                            retry_error=str(retry_error),
                        )
                        raise ThreatModelingError(
                            f"Asset processing failed after retry: {str(retry_error)}"
                        )
                else:
                    raise ThreatModelingError(f"Asset processing failed: {str(e)}")

        return wrapper

    return decorator
