import base64
import copy
import datetime
import decimal
import hashlib
import json
import time
import uuid
from urllib import error as url_error, request as url_request
from utils.powertools_compat import Logger, Tracer
from utils.aws_sdk_compat import boto3, ClientError
from utils.data_access_factory import get_database_access, get_storage_access
from utils.service_contracts import (
    AGENT_STATE_TABLE as CONTRACT_AGENT_STATE_TABLE,
    AGENT_TRAIL_TABLE as CONTRACT_AGENT_TRAIL_TABLE,
    ARCHITECTURE_BUCKET,
    BACKUP_TABLE as CONTRACT_BACKUP_TABLE,
    DEPLOYMENT_MODE,
    JOB_STATUS_TABLE as CONTRACT_JOB_STATUS_TABLE,
    REGION as CONTRACT_REGION,
    SHARING_TABLE as CONTRACT_SHARING_TABLE,
    THREAT_MODELING_AGENT,
    THREAT_MODELING_AGENT_STOP_URL,
    THREAT_MODELING_AGENT_URL,
)
from exceptions.exceptions import (
    InternalError,
    NotFoundError,
    UnauthorizedError,
    ConflictError,
)
from services.space_service import check_space_access
from utils.utils import create_dynamodb_item

STATE = CONTRACT_JOB_STATUS_TABLE
AGENT_CORE_RUNTIME = THREAT_MODELING_AGENT
AGENT_TABLE = CONTRACT_AGENT_STATE_TABLE
BACKUP_TABLE = CONTRACT_BACKUP_TABLE
AGENT_TRAIL_TABLE = CONTRACT_AGENT_TRAIL_TABLE
SHARING_TABLE = CONTRACT_SHARING_TABLE
REGION = CONTRACT_REGION
_dynamodb_access = None
_s3_access = None
_agent_core_client = None

# Backward-compatible injectable globals used by legacy tests.
dynamodb = None
table = None
agent_core_client = None
s3 = None
s3_pre = None


class _LegacyDynamoAccess:
    def __init__(self, dynamodb_resource):
        self._dynamodb_resource = dynamodb_resource

    def table(self, table_name: str):
        return self._dynamodb_resource.Table(table_name)

    def resource(self):
        return self._dynamodb_resource


class _LegacyS3Access:
    def __init__(self, client_obj, presign_obj=None):
        self._client_obj = client_obj
        self._presign_obj = presign_obj or client_obj

    def client(self):
        return self._client_obj

    def presign_client(self):
        return self._presign_obj

    def delete_object(self, bucket_name: str, object_key: str):
        return self._client_obj.delete_object(Bucket=bucket_name, Key=object_key)

    def object_exists(self, bucket_name: str, object_key: str) -> bool:
        try:
            self._client_obj.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except Exception:
            return False

    def generate_presigned_url(
        self,
        client_method: str,
        params: dict,
        expires_in: int,
        http_method: str,
    ) -> str:
        return self._presign_obj.generate_presigned_url(
            ClientMethod=client_method,
            Params=params,
            ExpiresIn=expires_in,
            HttpMethod=http_method,
        )

    def generate_presigned_put_object(
        self, bucket_name: str, object_key: str, file_type: str, expiration: int
    ) -> str:
        return self._presign_obj.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": file_type,
            },
            ExpiresIn=expiration,
            HttpMethod="PUT",
        )

    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> dict:
        return self._client_obj.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=data,
            ContentType=content_type,
        )


def _get_dynamodb_access():
    global _dynamodb_access
    if dynamodb is not None:
        return _LegacyDynamoAccess(dynamodb)

    if _dynamodb_access is not None:
        return _dynamodb_access

    _dynamodb_access = get_database_access(region_name=REGION)
    return _dynamodb_access


def _get_dynamodb():
    if dynamodb is not None:
        return dynamodb

    return _get_dynamodb_access().resource()


def _get_s3_access():
    global _s3_access
    if s3 is not None or s3_pre is not None:
        return _LegacyS3Access(s3 or s3_pre, s3_pre or s3)

    if _s3_access is not None:
        return _s3_access

    _s3_access = get_storage_access(region_name=REGION)
    return _s3_access


def _get_s3_client():
    if s3 is not None:
        return s3

    return _get_s3_access().client()


def _get_s3_presign_client():
    if s3_pre is not None:
        return s3_pre

    return _get_s3_access().presign_client()


def _get_agent_core_client():
    global _agent_core_client
    if agent_core_client is not None:
        return agent_core_client

    if _agent_core_client is not None:
        return _agent_core_client

    if DEPLOYMENT_MODE == "aws" and AGENT_CORE_RUNTIME:
        _agent_core_client = boto3.client("bedrock-agentcore", region_name=REGION)

    return _agent_core_client


LOG = Logger(serialize_stacktrace=False)
tracer = Tracer()


def _state_table():
    if table is not None:
        return table

    return _get_dynamodb_access().table(STATE)


def _trail_table():
    return _get_dynamodb_access().table(AGENT_TRAIL_TABLE)


def _backup_table():
    return _get_dynamodb_access().table(BACKUP_TABLE)


def convert_decimals(obj):
    """Recursively converts Decimal to float or int in a dictionary."""
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, decimal.Decimal):
        return (
            int(obj) if obj % 1 == 0 else float(obj)
        )  # Convert to int if it's a whole number
    else:
        return obj


def generate_random_uuid():
    return str(uuid.uuid4())


def _invoke_threat_model_agent(session_id: str, agent_input: dict) -> None:
    """Invoke threat modeling agent using AWS runtime or local HTTP endpoint."""
    payload = json.dumps({"input": agent_input})
    agent_core_client = _get_agent_core_client()

    if agent_core_client and AGENT_CORE_RUNTIME:
        agent_core_client.invoke_agent_runtime(
            agentRuntimeArn=AGENT_CORE_RUNTIME,
            runtimeSessionId=session_id,
            payload=payload,
        )
        return

    if not THREAT_MODELING_AGENT_URL:
        raise InternalError(
            "Threat modeling agent is not configured. Set THREAT_MODELING_AGENT for AWS "
            "or THREAT_MODELING_AGENT_URL for local mode."
        )

    endpoint = (
        THREAT_MODELING_AGENT_URL
        if THREAT_MODELING_AGENT_URL.endswith("/invocations")
        else f"{THREAT_MODELING_AGENT_URL}/invocations"
    )

    req = url_request.Request(
        endpoint,
        data=payload.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with url_request.urlopen(req, timeout=90) as response:
            if response.status >= 400:
                raise InternalError(
                    f"Threat modeling agent invocation failed with status {response.status}"
                )
    except url_error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
        raise InternalError(
            f"Threat modeling agent invocation failed ({e.code}): {detail}"
        )
    except url_error.URLError as e:
        raise InternalError(f"Threat modeling agent invocation failed: {e}")


def _stop_threat_model_session(session_id: str) -> None:
    """Stop threat modeling session using AWS runtime or optional local stop endpoint."""
    agent_core_client = _get_agent_core_client()
    if agent_core_client and AGENT_CORE_RUNTIME:
        response = agent_core_client.stop_runtime_session(
            runtimeSessionId=session_id,
            agentRuntimeArn=AGENT_CORE_RUNTIME,
        )
        LOG.info(
            f"Session {session_id} stopped successfully with response code: {response['statusCode']}"
        )
        return

    if not THREAT_MODELING_AGENT_STOP_URL:
        LOG.info(
            "Skipping session stop in local mode (THREAT_MODELING_AGENT_STOP_URL is not set)",
            session_id=session_id,
        )
        return

    payload = json.dumps({"session_id": session_id})
    req = url_request.Request(
        THREAT_MODELING_AGENT_STOP_URL,
        data=payload.encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with url_request.urlopen(req, timeout=15) as response:
            if response.status >= 400:
                LOG.warning(
                    "Local session stop endpoint returned non-success status",
                    status_code=response.status,
                    session_id=session_id,
                )
    except Exception as e:
        LOG.warning("Failed to stop local session", session_id=session_id, error=str(e))


def calculate_content_hash(data):
    """
    Calculate a hash of the threat model content to detect actual changes.

    This excludes metadata fields like timestamps, lock info, etc. and only
    hashes the actual threat model content (threats, assets, flows, etc.)

    Parameters:
    data (dict): The threat model data

    Returns:
    str: SHA256 hash of the content
    """
    # Extract only the content fields that matter for change detection
    content_fields = {
        "description": data.get("description"),
        "assumptions": data.get("assumptions"),
        "threat_list": data.get("threat_list"),
        "assets": data.get("assets"),
        "system_architecture": data.get("system_architecture"),
    }

    # Convert to JSON string with sorted keys for consistent hashing
    content_json = json.dumps(content_fields, sort_keys=True, default=str)

    # Calculate SHA256 hash
    return hashlib.sha256(content_json.encode("utf-8")).hexdigest()


def delete_s3_object(object_key, bucket_name=None):
    """
    Delete an object from an S3 bucket

    Parameters:
    bucket_name (str): Name of the S3 bucket
    object_key (str): Key/path of the object to delete

    Returns:
    dict: Response from S3 delete operation
    """
    if bucket_name is None:
        import os
        bucket_name = os.environ.get("ARCHITECTURE_BUCKET", ARCHITECTURE_BUCKET)
    try:
        response = _get_s3_access().delete_object(
            bucket_name=bucket_name,
            object_key=object_key,
        )
        return response

    except ClientError as e:
        print(f"Error deleting object {object_key} from bucket {bucket_name}: {e}")
        raise


def update_dynamodb_item(
    table,
    key,
    update_attrs,
    owner,
    locked_attributes=["owner", "s3_location", "job_id"],
):
    """
    Update an item in DynamoDB table with owner validation and attribute locking

    Parameters:
    table_name (str): Name of the DynamoDB table
    key (dict): Primary key of the item to update
    update_attrs (dict): Attributes to update and their new values
    owner (str): Owner attempting to update the item
    locked_attributes (list): List of attribute names that should not change
    """

    # Remove locked attributes from update_attrs
    update_attrs = {k: v for k, v in update_attrs.items() if k not in locked_attributes}

    # Create expression attribute names for reserved words
    expression_names = {}
    for attr in locked_attributes + list(update_attrs.keys()):
        expression_names[f"#attr_{attr}"] = attr

    # Add owner to expression names
    expression_names["#owner"] = "owner"

    # Build condition expression to check owner and ensure locked attributes haven't changed
    owner_condition = "#owner = :current_owner"
    locked_conditions = [
        f"attribute_not_exists(#attr_{attr}) OR #attr_{attr} = :old_{attr}"
        for attr in locked_attributes
    ]
    condition_expression = owner_condition + " AND " + " AND ".join(locked_conditions)

    try:
        # Get current values for locked attributes
        current_item = table.get_item(Key=key)["Item"]
        expression_values = {
            ":current_owner": owner,  # Add owner check
            **{f":old_{attr}": current_item[attr] for attr in locked_attributes},
        }

        # Add update values
        for i, (attr, value) in enumerate(update_attrs.items()):
            expression_values[f":val{i}"] = value

        # Build update expression using expression attribute names
        update_expression = "SET " + ", ".join(
            [f"#attr_{k} = :val{i}" for i, k in enumerate(update_attrs.keys())]
        )

        response = table.update_item(
            Key=key,
            UpdateExpression=update_expression,
            ConditionExpression=condition_expression,
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=expression_names,
            ReturnValues="ALL_NEW",
        )
        return convert_decimals(response.get("Attributes"))

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise UnauthorizedError(
                "Update rejected: Owner validation failed or locked attributes cannot be modified"
            )
        else:
            print(f"Error updating item: {e}")
        raise


def get_all_by_owner(table, owner: str):
    """
    Retrieves all items from DynamoDB table that match the specified owner using the owner-job-index.

    Args:
        table: DynamoDB table object
        owner (str): Owner identifier to query for

    Returns:
        list: List of dictionary items matching the owner. Empty list if no matches found.

    Raises:
        InternalError: If DynamoDB query fails
    """
    try:
        query_params = {
            "IndexName": "owner-job-index",
            "KeyConditionExpression": "#owner = :owner_value",
            "ProjectionExpression": _CATALOG_PROJECTION,
            "ExpressionAttributeNames": {**_CATALOG_PROJECTION_NAMES},
            "ExpressionAttributeValues": {":owner_value": owner},
        }

        all_items = []
        while True:
            response = table.query(**query_params)
            all_items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_params["ExclusiveStartKey"] = last_key

        return all_items
    except Exception as e:
        LOG.error(e)
        raise InternalError(e)


def delete_dynamodb_item(table, key, owner):
    """
    Delete an item from DynamoDB table only if owner matches

    Parameters:
    table (boto3.resource.Table): DynamoDB table resource
    key (dict): Primary key of the item to delete
    owner (str): Owner attempting to delete the item
    """
    try:
        # Create condition expression to check owner
        condition_expression = "#owner = :owner"

        response = table.delete_item(
            Key=key,
            ConditionExpression=condition_expression,
            ExpressionAttributeNames={"#owner": "owner"},
            ExpressionAttributeValues={":owner": owner},
        )
        return response

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise UnauthorizedError("Delete rejected: Owner validation failed")
        else:
            print(f"Error deleting item: {e}")
        raise


@tracer.capture_method
def invoke_lambda(owner, payload):
    s3_location = payload.get("s3_location")
    iteration = payload.get("iteration")
    reasoning = payload.get("reasoning", 0)
    instructions = payload.get("instructions", None)
    is_replay = payload.get("replay", False)
    is_version = payload.get("version", False)
    image_type = payload.get("image_type", None)
    application_type = payload.get("application_type", "hybrid")
    space_id = payload.get("space_id") or None

    if space_id and owner != "MCP":
        check_space_access(space_id, owner)

    if is_replay:
        id = payload.get("id")
    else:
        id = generate_random_uuid()

    # Version-specific fields
    previous_job_id = payload.get("id") if is_version else None
    mirror_attack_trees = (
        payload.get("mirror_attack_trees", False) if is_version else False
    )
    mirror_sharing = payload.get("mirror_sharing", False) if is_version else False

    description = payload.get("description", " ")
    assumptions = payload.get("assumptions", [])
    title = payload.get("title", " ")
    session_id = str(uuid.uuid4())
    LOG.info(f"Agent invoked with session: {session_id}")

    try:
        # Step 1: Reset any cancelled flag and set state to START
        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        state_item = {
            "id": id,
            "state": "START",
            "owner": owner,
            "session_id": session_id,
            "execution_owner": owner,
            "updated_at": current_time,
        }
        if is_version and previous_job_id:
            state_item["parent_id"] = previous_job_id
            state_item["mirror_attack_trees"] = mirror_attack_trees
        _state_table().put_item(Item=state_item)
        LOG.info(f"State initialized to START for job {id}")

        # Step 2: If this is a replay, store backup in the dedicated backup table
        if is_replay:
            agent_table = _get_dynamodb_access().table(AGENT_TABLE)

            response = agent_table.get_item(Key={"job_id": id})

            if "Item" in response:
                backup_data = copy.deepcopy(response["Item"])
                _backup_table().put_item(Item=backup_data)

                LOG.info(f"Backup stored in backup table for job_id: {id}")
            else:
                LOG.warning(f"Item not found for backup during replay: {id}")

        # Step 2b: If version with mirror_sharing, copy sharing records from parent
        if is_version and mirror_sharing and previous_job_id:
            _copy_sharing_records(previous_job_id, id)

        # Step 3: Invoke the agent
        agent_input = {
            "s3_location": s3_location,
            "id": id,
            "reasoning": reasoning,
            "iteration": iteration,
            "description": description,
            "assumptions": assumptions,
            "owner": owner,
            "title": title,
            "replay": is_replay,
            "instructions": instructions,
            "image_type": image_type,
            "application_type": application_type,
            "space_id": space_id,
        }

        if is_version:
            agent_input["version"] = True
            agent_input["previous_job_id"] = previous_job_id
            agent_input["mirror_attack_trees"] = mirror_attack_trees

        _invoke_threat_model_agent(session_id, agent_input)

        agent_state = {
            "job_id": id,
            "s3_location": s3_location,
            "owner": owner,
            "title": title,
            "retry": reasoning,
        }
        if space_id:
            agent_state["space_id"] = space_id
        if is_version and previous_job_id:
            agent_state["parent_id"] = previous_job_id

        if not is_replay:
            # For version, set is_shared if sharing was mirrored
            if is_version and mirror_sharing:
                agent_state["is_shared"] = True
            create_dynamodb_item(agent_state, AGENT_TABLE)

        return {"id": id}
    except Exception as e:
        LOG.error(e)
        # Update state to FAILED on error
        try:
            current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
            _state_table().update_item(
                Key={"id": id},
                UpdateExpression="SET #state = :state, #updated_at = :updated_at",
                ExpressionAttributeNames={
                    "#state": "state",
                    "#updated_at": "updated_at",
                },
                ExpressionAttributeValues={
                    ":state": "FAILED",
                    ":updated_at": current_time,
                },
            )
            LOG.info(f"State updated to FAILED for job {id}")
        except Exception as update_error:
            LOG.error(f"Failed to update state to FAILED: {update_error}")
        raise InternalError(e)


def _copy_sharing_records(source_job_id, target_job_id):
    """Copy sharing records from one threat model to another."""
    try:
        sharing_table = _get_dynamodb_access().table(SHARING_TABLE)
        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Query all sharing records for the source (with pagination)
        items = []
        query_params = {
            "KeyConditionExpression": "threat_model_id = :tm_id",
            "ExpressionAttributeValues": {":tm_id": source_job_id},
        }
        while True:
            response = sharing_table.query(**query_params)
            items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_params["ExclusiveStartKey"] = last_key

        with sharing_table.batch_writer() as batch:
            for item in items:
                new_item = copy.deepcopy(item)
                new_item["threat_model_id"] = target_job_id
                new_item["shared_at"] = current_time
                batch.put_item(Item=new_item)

        LOG.info(
            f"Copied {len(items)} sharing records from {source_job_id} to {target_job_id}"
        )
    except Exception as e:
        LOG.error(f"Failed to copy sharing records: {e}")


def _delete_sharing_records(job_id):
    """Delete all sharing records for a threat model."""
    try:
        sharing_table = _get_dynamodb_access().table(SHARING_TABLE)
        response = sharing_table.query(
            KeyConditionExpression="threat_model_id = :tm_id",
            ExpressionAttributeValues={":tm_id": job_id},
        )
        items = response.get("Items", [])
        if items:
            with sharing_table.batch_writer() as batch:
                for item in items:
                    batch.delete_item(
                        Key={
                            "threat_model_id": item["threat_model_id"],
                            "user_id": item["user_id"],
                        }
                    )
            LOG.info(f"Deleted {len(items)} sharing records for {job_id}")
    except Exception as e:
        LOG.error(f"Failed to delete sharing records: {e}")


def _retry_field_as_int(item: dict) -> int:
    """Coerce job retry count for API responses; DB/Postgres may store null."""
    raw = item.get("retry", 0)
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


@tracer.capture_method
def check_status(job_id):
    try:
        # Attempt to get the item from the DynamoDB table
        response = _state_table().get_item(Key={"id": job_id})

        # Check if the item exists
        if "Item" in response:
            item = response["Item"]
            status = item.get("state", "Unknown")
            detail = item.get("detail")
            session_id = item.get("session_id")
            execution_owner = item.get("execution_owner")

            result = {
                "id": job_id,
                "state": status,
                "retry": _retry_field_as_int(item),
                "session_id": session_id,
            }

            # Only include detail if it exists
            if detail is not None:
                result["detail"] = detail

            # Include execution_owner if it exists
            if execution_owner is not None:
                result["execution_owner"] = execution_owner

            return result
        else:
            return {"id": job_id, "state": "Not Found"}

    except Exception as e:
        print(e)
        raise InternalError(e)


def _generate_fallback_trail(job_id, agent_item):
    if not agent_item:
        return {"id": job_id}

    title = agent_item.get("title", "Threat Model")
    desc = agent_item.get("description", "No description provided.")
    app_type = agent_item.get("application_type", "Not specified")

    assumptions_list = agent_item.get("assumptions", [])
    assumptions_md = "\n".join(f"- {a}" for a in assumptions_list) if assumptions_list else "- None"
    space_context = f"""### Analysis Context for **{title}**

- **Application Type**: {app_type}
- **Description**: {desc}

#### Assumptions:
{assumptions_md}
"""

    assets_list = agent_item.get("assets", {}).get("assets", [])
    assets_parts = []
    if assets_list:
        for asset in assets_list:
            name = asset.get("name", "Unnamed Asset")
            atype = asset.get("type", "Unknown")
            adesc = asset.get("description", "No description.")
            assets_parts.append(f"* **{name}** (Type: *{atype}*)\n  - {adesc}")
        assets_content = "### Identified Assets\n\n" + "\n\n".join(assets_parts)
    else:
        assets_content = "No assets were defined for this model."

    flows_list = agent_item.get("system_architecture", {}).get("data_flows", [])
    boundaries_list = agent_item.get("system_architecture", {}).get("trust_boundaries", [])

    flows_parts = []
    if boundaries_list:
        flows_parts.append("#### Trust Boundaries:")
        for tb in boundaries_list:
            source = tb.get("source_entity", "Unknown")
            target = tb.get("target_entity", "Unknown")
            purpose = tb.get("purpose", "No description.")
            flows_parts.append(f"- **Boundary ({source} &harr; {target})**: {purpose}")

    if flows_list:
        if flows_parts:
            flows_parts.append("")
        flows_parts.append("#### Data Flows:")
        for df in flows_list:
            source = df.get("source_entity", "Unknown")
            target = df.get("target_entity", "Unknown")
            flow_desc = df.get("flow_description", "No description.")
            flows_parts.append(f"- **Flow ({source} &rarr; {target})**: {flow_desc}")

    if flows_parts:
        flows_content = "### System Architecture & Data Flows\n\n" + "\n".join(flows_parts)
    else:
        flows_content = "No data flows or trust boundaries defined."

    threats_list = agent_item.get("threat_list", {}).get("threats", [])
    threats_content_list = []
    if threats_list:
        for idx, threat in enumerate(threats_list):
            t_title = threat.get("title", "Unnamed Threat")
            t_desc = threat.get("description", "No description.")
            t_stride = threat.get("stride_category", "N/A")
            t_target = threat.get("target", "N/A")
            t_like = threat.get("likelihood", "N/A")
            t_mit = threat.get("remediation", "No mitigation specified.")

            threats_content_list.append(f"""### Threat {idx + 1}: {t_title}

- **STRIDE Category**: {t_stride}
- **Target Asset**: {t_target}
- **Likelihood**: {t_like}

#### Threat Description:
{t_desc}

#### Remediation / Mitigation:
{t_mit}
""")

    return {
        "id": job_id,
        "assets": assets_content,
        "flows": flows_content,
        "gaps": [],
        "threats": threats_content_list,
        "space_context": space_context,
    }


@tracer.capture_method
def check_trail(job_id):
    try:
        # Attempt to get the item from the DynamoDB table
        response = _trail_table().get_item(Key={"id": job_id})

        # Check if the item exists and has content
        if "Item" in response:
            item = response["Item"]
            assets = item.get("assets", "")
            flows = item.get("flows", "")
            gaps = item.get("gap", [])
            threats = item.get("threats", [])
            space_context = item.get("space_context", "")
            if assets or flows or threats or space_context:
                return {
                    "id": job_id,
                    "assets": assets,
                    "flows": flows,
                    "gaps": gaps,
                    "threats": threats,
                    "space_context": space_context,
                }

        # Fallback to generating a trail from the threat model results
        try:
            agent_table = _get_dynamodb_access().table(AGENT_TABLE)
            agent_resp = agent_table.get_item(Key={"job_id": job_id})
            if "Item" in agent_resp:
                return _generate_fallback_trail(job_id, convert_decimals(agent_resp["Item"]))
        except Exception as e:
            print(f"Failed to generate fallback trail: {e}")

        return {"id": job_id}

    except Exception as e:
        print(e)
        raise InternalError(e)


@tracer.capture_method
def fetch_results(job_id, user_id=None):
    table = _get_dynamodb_access().table(AGENT_TABLE)

    try:
        response = table.get_item(Key={"job_id": job_id})

        if "Item" in response:
            item = convert_decimals(response["Item"])

            # Add access information if user_id is provided
            if user_id and user_id != "MCP":
                from services.collaboration_service import check_access

                access_info = check_access(job_id, user_id)

                # Check if user has access
                if not access_info["has_access"]:
                    LOG.warning(
                        f"User {user_id} does not have access to threat model {job_id}"
                    )
                    raise UnauthorizedError(
                        "You do not have access to this threat model"
                    )

                # Add access information to response
                item["is_owner"] = access_info["is_owner"]
                item["access_level"] = access_info["access_level"]

            # Ensure last_modified_at exists for version tracking
            if "last_modified_at" not in item:
                # Set initial timestamp if not present
                current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                item["last_modified_at"] = current_time

            return {
                "job_id": job_id,
                "state": "Found",
                "item": item,
            }
        else:
            return {"job_id": job_id, "state": "Not Found", "item": None}

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(e)
        raise InternalError(e)


@tracer.capture_method
def update_results(job_id, payload, owner, lock_token=None):
    table = _get_dynamodb_access().table(AGENT_TABLE)

    try:
        # For non-MCP users, check access and verify lock
        if owner != "MCP":
            from utils.authorization import require_access
            from services.lock_service import get_lock_status

            # Check if user has edit access (will raise UnauthorizedError if not)
            require_access(job_id, owner, required_level="EDIT")

            # Verify user holds valid lock (everyone including owner must have lock)
            lock_status = get_lock_status(job_id)

            if not lock_status.get("locked"):
                LOG.warning(f"No active lock for threat model {job_id}")
                raise UnauthorizedError("You must acquire a lock before editing")

            if lock_status.get("user_id") != owner:
                LOG.warning(
                    f"Lock for {job_id} held by {lock_status.get('user_id')}, not {owner}"
                )
                raise UnauthorizedError("Lock is held by another user")

            # Validate lock token if provided
            if lock_token and lock_status.get("lock_token") != lock_token:
                LOG.warning(f"Invalid lock token for threat model {job_id}")
                raise UnauthorizedError("Invalid lock token")

            # Get current server state for conflict detection and hash comparison
            current_item_response = table.get_item(Key={"job_id": job_id})
            current_item = None
            if "Item" in current_item_response:
                current_item = current_item_response["Item"]

            # Check for version conflict
            client_timestamp = payload.get("client_last_modified_at")
            if client_timestamp and current_item:
                server_timestamp = current_item.get("last_modified_at")

                # Compare timestamps - if server is newer, there's a conflict
                if server_timestamp and server_timestamp > client_timestamp:
                    LOG.warning(
                        f"Version conflict for {job_id}: server={server_timestamp}, client={client_timestamp}"
                    )
                    raise ConflictError(
                        {
                            "message": "The threat model has been modified by another user",
                            "server_timestamp": server_timestamp,
                            "client_timestamp": client_timestamp,
                            "server_state": convert_decimals(current_item),
                        }
                    )

            # Calculate content hash to detect actual changes
            new_content_hash = calculate_content_hash(payload)

            # Get previous content hash
            previous_content_hash = (
                current_item.get("content_hash") if current_item else None
            )

            # Only update timestamp and last_modified_by if content actually changed
            if new_content_hash != previous_content_hash:
                current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                payload["last_modified_by"] = owner
                payload["last_modified_at"] = current_time
                payload["content_hash"] = new_content_hash
                LOG.info(f"Content changed for {job_id}, updating timestamp")
            else:
                # Content hasn't changed, preserve existing timestamp
                if current_item:
                    payload["last_modified_at"] = current_item.get("last_modified_at")
                    payload["last_modified_by"] = current_item.get(
                        "last_modified_by", owner
                    )
                payload["content_hash"] = new_content_hash
                LOG.info(f"No content changes for {job_id}, preserving timestamp")

            # Remove client_last_modified_at from payload before saving
            payload.pop("client_last_modified_at", None)

        key = {"job_id": job_id}
        return update_dynamodb_item(table, key, payload, owner)

    except (UnauthorizedError, ConflictError):
        raise
    except Exception as e:
        LOG.error(e)
        raise


@tracer.capture_method
def restore(job_id, owner):
    agent_table = _get_dynamodb_access().table(AGENT_TABLE)
    state_table = _get_dynamodb_access().table(STATE)

    try:
        response = agent_table.get_item(Key={"job_id": job_id}, ConsistentRead=True)

        if "Item" not in response:
            LOG.warning(f"Item {job_id} not found")
            raise NotFoundError

        item = response["Item"]

        # Check if user has access (owner or EDIT permission)
        if owner != "MCP":
            from utils.authorization import require_access

            # This will raise UnauthorizedError if user doesn't have access
            # For restore, we need at least EDIT access
            require_access(job_id, owner, required_level="EDIT")

        backup_response = _backup_table().get_item(Key={"job_id": job_id})
        if "Item" not in backup_response:
            LOG.warning(f"No backup found for job {job_id}")
            raise NotFoundError

        backup_data = backup_response["Item"]

        agent_table.put_item(Item=backup_data)

        # Clean up the backup after successful restore
        try:
            _backup_table().delete_item(Key={"job_id": job_id})
        except Exception as e:
            LOG.warning(f"Failed to delete backup for {job_id}: {e}")

        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        state_response = state_table.get_item(Key={"id": job_id})
        if "Item" in state_response:
            retry = _retry_field_as_int(state_response["Item"])
        else:
            retry = 0

        # Use the actual owner from the item, not the requester
        actual_owner = item.get("owner")

        state_table.put_item(
            Item={
                "id": job_id,
                "owner": actual_owner,
                "retry": retry,
                "state": "COMPLETE",
                "cancelled": True,
                "updated_at": current_time,
            }
        )
        LOG.info(f"Restore completed for job {job_id} with cancelled flag set")

        return True
    except Exception as e:
        LOG.error(f"Failed to restore job {job_id}: {str(e)}")
        raise InternalError


def validate_pagination_params(limit, filter_mode):
    """
    Validate pagination parameters.

    Args:
        limit: Page size
        filter_mode: Filter mode

    Raises:
        ValueError: If parameters are invalid
    """
    # Validate page size
    valid_page_sizes = [10, 20, 50, 100]
    if limit not in valid_page_sizes:
        raise ValueError(f"Page size must be one of {valid_page_sizes}")

    # Validate filter mode
    valid_filters = ["owned", "shared", "all"]
    if filter_mode not in valid_filters:
        raise ValueError(f"Filter mode must be one of {valid_filters}")


def decode_cursor(cursor_str):
    """
    Decode and validate pagination cursor.

    Args:
        cursor_str: Base64-encoded JSON cursor string

    Returns:
        dict: Decoded cursor with 'owned', 'shared', and 'filter' keys

    Raises:
        ValueError: If cursor is invalid or malformed
    """
    if not cursor_str:
        return None

    try:
        # Decode base64
        decoded_bytes = base64.b64decode(cursor_str)
        cursor_data = json.loads(decoded_bytes.decode("utf-8"))

        # Validate cursor structure
        if not isinstance(cursor_data, dict):
            raise ValueError("Cursor must be a JSON object")

        # Extract keys (they may be None if that query is exhausted)
        owned_key = cursor_data.get("owned")
        shared_key = cursor_data.get("shared")
        filter_mode = cursor_data.get("filter", "all")

        return {"owned": owned_key, "shared": shared_key, "filter": filter_mode}
    except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        LOG.warning(f"Invalid cursor format: {e}")
        raise ValueError("Invalid pagination cursor")


def encode_cursor(owned_key, shared_key, filter_mode):
    """
    Encode pagination state into a cursor string.

    Args:
        owned_key: DynamoDB LastEvaluatedKey for owned query (or None)
        shared_key: DynamoDB LastEvaluatedKey for shared query (or None)
        filter_mode: Current filter mode ('owned', 'shared', or 'all')

    Returns:
        str: Base64-encoded cursor, or None if both keys are None
    """
    # If both keys are None, there's no next page
    if owned_key is None and shared_key is None:
        return None

    cursor_data = {"owned": owned_key, "shared": shared_key, "filter": filter_mode}

    # Encode to JSON then base64
    cursor_json = json.dumps(cursor_data, default=str)
    cursor_bytes = cursor_json.encode("utf-8")
    cursor_b64 = base64.b64encode(cursor_bytes).decode("utf-8")

    return cursor_b64


def encode_single_cursor(last_evaluated_key: dict) -> str | None:
    """
    Encode a single DynamoDB LastEvaluatedKey into a base64 cursor string.

    Args:
        last_evaluated_key: DynamoDB LastEvaluatedKey dict

    Returns:
        Base64-encoded cursor string, or None if key is None/empty
    """
    if not last_evaluated_key:
        return None

    cursor_json = json.dumps(last_evaluated_key, default=str)
    cursor_bytes = cursor_json.encode("utf-8")
    return base64.b64encode(cursor_bytes).decode("utf-8")


# Fields to fetch from DynamoDB for catalog listing (avoids reading heavy fields)
_CATALOG_PROJECTION = "job_id, #owner, title, summary, #ts, s3_location, threat_list"
_CATALOG_PROJECTION_NAMES = {"#owner": "owner", "#ts": "timestamp"}


def _slim_catalog_item(item: dict) -> dict:
    """
    Return a lightweight copy of a threat model item for catalog listing.
    Keeps only the fields the UI needs and computes pre-aggregated stats
    from threat_list so the frontend doesn't need to iterate threats.
    """
    slim = {
        "job_id": item.get("job_id"),
        "owner": item.get("owner"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "timestamp": item.get("timestamp"),
        "s3_location": item.get("s3_location"),
        "is_owner": item.get("is_owner"),
        "access_level": item.get("access_level"),
        "shared_by": item.get("shared_by"),
    }

    # Compute likelihood counts server-side
    high = 0
    medium = 0
    low = 0
    threat_list = item.get("threat_list")
    if isinstance(threat_list, dict):
        threats = threat_list.get("threats")
        if isinstance(threats, list):
            for t in threats:
                if isinstance(t, dict):
                    likelihood = t.get("likelihood")
                    if likelihood == "High":
                        high += 1
                    elif likelihood == "Medium":
                        medium += 1
                    elif likelihood == "Low":
                        low += 1

    slim["stats"] = {
        "total": high + medium + low,
        "high": high,
        "medium": medium,
        "low": low,
    }

    return slim


def decode_single_cursor(cursor_str: str) -> dict | None:
    """
    Decode and validate a base64 cursor string back into a DynamoDB ExclusiveStartKey.

    Args:
        cursor_str: Base64-encoded JSON cursor string

    Returns:
        Decoded dict, or None if cursor_str is falsy

    Raises:
        ValueError: If cursor is invalid or malformed
    """
    if not cursor_str:
        return None

    try:
        decoded_bytes = base64.b64decode(cursor_str)
        cursor_data = json.loads(decoded_bytes.decode("utf-8"))

        if not isinstance(cursor_data, dict):
            raise ValueError("Cursor must be a JSON object")

        return cursor_data
    except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        LOG.warning(f"Invalid single cursor format: {e}")
        raise ValueError("Invalid pagination cursor")


@tracer.capture_method
def fetch_owned_paginated(owner: str, limit: int, cursor: str = None) -> dict:
    """
    Fetch owned threat models with cursor-based pagination, sorted newest-first.

    Args:
        owner: User ID
        limit: Page size (must be one of 10, 20, 50, 100)
        cursor: Base64-encoded cursor string for next page (optional)

    Returns:
        dict with 'catalogs' and 'pagination' keys

    Raises:
        ValueError: If limit is invalid or cursor is malformed
    """
    valid_page_sizes = [10, 20, 50, 100]
    if limit not in valid_page_sizes:
        raise ValueError(f"Page size must be one of {valid_page_sizes}")

    state_table = _get_dynamodb_access().table(AGENT_TABLE)

    exclusive_start_key = decode_single_cursor(cursor) if cursor else None

    try:
        query_params = {
            "IndexName": "owner-timestamp-index",
            "KeyConditionExpression": "#owner = :owner_value",
            "ProjectionExpression": _CATALOG_PROJECTION,
            "ExpressionAttributeNames": {**_CATALOG_PROJECTION_NAMES},
            "ExpressionAttributeValues": {":owner_value": owner},
            "ScanIndexForward": False,
            "Limit": limit + 1,
        }

        if exclusive_start_key:
            query_params["ExclusiveStartKey"] = exclusive_start_key

        response = state_table.query(**query_params)

        items = response.get("Items", [])

        # Determine if there's a next page by checking if we got more than limit
        has_next_page = len(items) > limit
        if has_next_page:
            items = items[:limit]

        for item in items:
            item["is_owner"] = True
            item["access_level"] = "OWNER"

        slim_items = [_slim_catalog_item(item) for item in items]

        # Build cursor from the last item's key attributes if there's a next page
        next_cursor = None
        if has_next_page and items:
            last_item = items[-1]
            next_cursor = encode_single_cursor(
                {
                    "owner": last_item["owner"],
                    "job_id": last_item["job_id"],
                    "timestamp": last_item["timestamp"],
                }
            )

        return {
            "catalogs": convert_decimals(slim_items),
            "pagination": {
                "hasNextPage": has_next_page,
                "cursor": next_cursor,
                "totalReturned": len(items),
            },
        }
    except ValueError:
        raise
    except Exception as e:
        LOG.error(f"Error fetching owned paginated: {e}")
        raise InternalError(e)


@tracer.capture_method
def fetch_shared_paginated(user_id: str, limit: int, cursor: str = None) -> dict:
    """
    Fetch shared threat models with cursor-based pagination, sorted newest-first.

    Args:
        user_id: User ID
        limit: Page size (must be one of 10, 20, 50, 100)
        cursor: Base64-encoded cursor string for next page (optional)

    Returns:
        dict with 'catalogs' and 'pagination' keys

    Raises:
        ValueError: If limit is invalid or cursor is malformed
    """
    valid_page_sizes = [10, 20, 50, 100]
    if limit not in valid_page_sizes:
        raise ValueError(f"Page size must be one of {valid_page_sizes}")

    sharing_table = _get_dynamodb_access().table(SHARING_TABLE)

    exclusive_start_key = decode_single_cursor(cursor) if cursor else None

    try:
        query_params = {
            "IndexName": "user-timestamp-index",
            "KeyConditionExpression": "#user_id = :user_id",
            "ExpressionAttributeNames": {"#user_id": "user_id"},
            "ExpressionAttributeValues": {":user_id": user_id},
            "ScanIndexForward": False,
            "Limit": limit + 1,
        }

        if exclusive_start_key:
            query_params["ExclusiveStartKey"] = exclusive_start_key

        sharing_response = sharing_table.query(**query_params)

        sharing_records = sharing_response.get("Items", [])

        # Determine if there's a next page by checking if we got more than limit
        has_next_page = len(sharing_records) > limit
        if has_next_page:
            sharing_records = sharing_records[:limit]

        # Batch-fetch full threat model records from state table
        threat_model_ids = [r["threat_model_id"] for r in sharing_records]
        threat_models = _batch_fetch_threat_models(threat_model_ids)

        # Enrich records, skipping any where the threat model no longer exists or is owned by user
        items = []
        for sharing_record in sharing_records:
            tm_id = sharing_record["threat_model_id"]
            tm = threat_models.get(tm_id)
            if tm is None:
                continue
            if tm.get("owner") == user_id:
                continue
            tm["is_owner"] = False
            tm["access_level"] = sharing_record["access_level"]
            tm["shared_by"] = sharing_record.get("shared_by")
            items.append(tm)

        slim_items = [_slim_catalog_item(item) for item in items]

        # Build cursor from the last sharing record's key attributes if there's a next page
        next_cursor = None
        if has_next_page and sharing_records:
            last_record = sharing_records[-1]
            next_cursor = encode_single_cursor(
                {
                    "threat_model_id": last_record["threat_model_id"],
                    "user_id": last_record["user_id"],
                    "shared_at": last_record["shared_at"],
                }
            )

        return {
            "catalogs": convert_decimals(slim_items),
            "pagination": {
                "hasNextPage": has_next_page,
                "cursor": next_cursor,
                "totalReturned": len(items),
            },
        }
    except ValueError:
        raise
    except Exception as e:
        LOG.error(f"Error fetching shared paginated: {e}")
        raise InternalError(e)


def query_owned_paginated(table, owner, limit, exclusive_start_key=None):
    """
    Query owned threat models with pagination.

    Args:
        table: DynamoDB table resource
        owner: User ID
        limit: Maximum number of items to return
        exclusive_start_key: DynamoDB key to start from (for pagination)

    Returns:
        dict: {
            'items': List of threat model items,
            'last_evaluated_key': DynamoDB key for next page (or None)
        }
    """
    try:
        query_params = {
            "IndexName": "owner-job-index",
            "KeyConditionExpression": "#owner = :owner_value",
            "ExpressionAttributeNames": {"#owner": "owner"},
            "ExpressionAttributeValues": {":owner_value": owner},
            "Limit": limit,
        }

        if exclusive_start_key:
            query_params["ExclusiveStartKey"] = exclusive_start_key

        response = table.query(**query_params)

        return {
            "items": response.get("Items", []),
            "last_evaluated_key": response.get("LastEvaluatedKey"),
        }
    except Exception as e:
        LOG.error(f"Error querying owned threat models: {e}")
        raise InternalError(e)


def query_shared_paginated(
    sharing_table, table, owner, limit, exclusive_start_key=None
):
    """
    Query shared threat models with pagination.

    Args:
        sharing_table: DynamoDB sharing table resource
        table: DynamoDB agent table resource
        owner: User ID
        limit: Maximum number of items to return
        exclusive_start_key: DynamoDB key to start from (for pagination)

    Returns:
        dict: {
            'items': List of threat model items with sharing info,
            'last_evaluated_key': DynamoDB key for next page (or None)
        }
    """
    try:
        query_params = {
            "IndexName": "user-index",
            "KeyConditionExpression": "#user_id = :user_id",
            "ExpressionAttributeNames": {"#user_id": "user_id"},
            "ExpressionAttributeValues": {":user_id": owner},
            "Limit": limit,
        }

        if exclusive_start_key:
            query_params["ExclusiveStartKey"] = exclusive_start_key

        sharing_response = sharing_table.query(**query_params)

        # Fetch full threat model details for each shared record
        shared_items = []
        for sharing_record in sharing_response.get("Items", []):
            threat_model_id = sharing_record["threat_model_id"]
            tm_response = table.get_item(Key={"job_id": threat_model_id})

            if "Item" in tm_response:
                item = tm_response["Item"]
                # Add access information
                item["is_owner"] = False
                item["access_level"] = sharing_record["access_level"]
                item["shared_by"] = sharing_record.get("shared_by")
                shared_items.append(item)

        return {
            "items": shared_items,
            "last_evaluated_key": sharing_response.get("LastEvaluatedKey"),
        }
    except Exception as e:
        LOG.error(f"Error querying shared threat models: {e}")
        raise InternalError(e)


def _get_all_shared(sharing_table, table, owner):
    """
    Query all shared threat models for a user (no pagination).

    Args:
        sharing_table: DynamoDB sharing table resource
        table: DynamoDB agent table resource
        owner: User ID

    Returns:
        list: List of threat model items with sharing info
    """
    try:
        query_params = {
            "IndexName": "user-index",
            "KeyConditionExpression": "#user_id = :user_id",
            "ExpressionAttributeNames": {"#user_id": "user_id"},
            "ExpressionAttributeValues": {":user_id": owner},
        }

        # Paginate through all sharing records
        all_sharing_records = []
        while True:
            sharing_response = sharing_table.query(**query_params)
            all_sharing_records.extend(sharing_response.get("Items", []))
            last_key = sharing_response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_params["ExclusiveStartKey"] = last_key

        # Fetch slim threat model details for each shared record
        shared_items = []
        for sharing_record in all_sharing_records:
            threat_model_id = sharing_record["threat_model_id"]
            tm_response = table.get_item(
                Key={"job_id": threat_model_id},
                ProjectionExpression=_CATALOG_PROJECTION,
                ExpressionAttributeNames=_CATALOG_PROJECTION_NAMES,
            )

            if "Item" in tm_response:
                item = tm_response["Item"]
                item["is_owner"] = False
                item["access_level"] = sharing_record["access_level"]
                item["shared_by"] = sharing_record.get("shared_by")
                shared_items.append(item)

        return shared_items
    except Exception as e:
        LOG.error(f"Error querying all shared threat models: {e}")
        raise InternalError(e)


@tracer.capture_method
@tracer.capture_method
def fetch_all(owner, limit=None, cursor=None, filter_mode="all"):
    """
    Fetch threat models for a user with pagination.

    Args:
        owner: User ID
        limit: Page size (10, 20, 50, 100) or None
        cursor: Pagination cursor (Base64-encoded JSON) or None
        filter_mode: Filter mode - "owned", "shared", or "all" (default: "all")

    Returns:
        dict: {
            "catalogs": [...],
            "pagination": {
                "hasNextPage": bool,
                "cursor": str | None,
                "totalReturned": int
            }
        }
    """
    table = _get_dynamodb_access().table(AGENT_TABLE)
    sharing_table = _get_dynamodb_access().table(SHARING_TABLE)
    LOG.info(f"Fetching items for owner: {owner}, limit: {limit}, cursor: {cursor}, filter: {filter_mode}")

    try:
        # Validate limit if provided, and filter mode
        if limit is not None:
            validate_pagination_params(limit, filter_mode)
        else:
            # If limit is not specified, validate only the filter mode
            valid_filters = ["owned", "shared", "all"]
            if filter_mode not in valid_filters:
                raise ValueError(f"Filter mode must be one of {valid_filters}")

        # Decode cursor
        cursor_data = decode_cursor(cursor) if cursor else None
        
        owned_cursor = None
        shared_cursor = None
        if cursor_data:
            # Verify the cursor filter matches current filter mode
            if cursor_data.get("filter") != filter_mode:
                raise ValueError("Cursor filter mode mismatch")
            owned_cursor = cursor_data.get("owned")
            shared_cursor = cursor_data.get("shared")

        owned_items = []
        shared_items = []
        owned_last_key = None
        shared_last_key = None

        # 1. Fetch owned items
        if filter_mode in ["owned", "all"]:
            if limit is not None:
                query_result = query_owned_paginated(
                    table, owner, limit, exclusive_start_key=owned_cursor
                )
                owned_items = query_result.get("items", [])
                owned_last_key = query_result.get("last_evaluated_key")
            else:
                owned_items = get_all_by_owner(table, owner)

            for item in owned_items:
                item["is_owner"] = True
                item["access_level"] = "OWNER"

        # 2. Fetch shared items
        if filter_mode in ["shared", "all"] and owner != "MCP":
            if limit is not None:
                query_result = query_shared_paginated(
                    sharing_table, table, owner, limit, exclusive_start_key=shared_cursor
                )
                shared_items = query_result.get("items", [])
                shared_last_key = query_result.get("last_evaluated_key")
            else:
                shared_items = _get_all_shared(sharing_table, table, owner)

        # 3. Combine and sort
        combined = owned_items + shared_items
        combined.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        # 4. Handle pagination slicing
        if limit is None:
            returned_items = combined
            hasNextPage = False
            next_cursor = None
        else:
            if len(combined) > limit:
                returned_items = combined[:limit]
                hasNextPage = True

                # Adjust pagination keys for cursor
                returned_owned = [x for x in returned_items if x.get("is_owner") is True]
                returned_shared = [x for x in returned_items if x.get("is_owner") is False]

                next_owned_key = None
                if len(returned_owned) < len(owned_items):
                    if returned_owned:
                        # Last returned owned item key
                        next_owned_key = {"job_id": returned_owned[-1]["job_id"]}
                    else:
                        next_owned_key = owned_cursor
                else:
                    next_owned_key = owned_last_key

                next_shared_key = None
                if len(returned_shared) < len(shared_items):
                    if returned_shared:
                        # Last returned shared item key
                        next_shared_key = {
                            "threat_model_id": returned_shared[-1]["job_id"],
                            "user_id": owner,
                        }
                    else:
                        next_shared_key = shared_cursor
                else:
                    next_shared_key = shared_last_key

                next_cursor = encode_cursor(next_owned_key, next_shared_key, filter_mode)
            else:
                returned_items = combined
                hasNextPage = (owned_last_key is not None) or (shared_last_key is not None)
                next_cursor = encode_cursor(owned_last_key, shared_last_key, filter_mode) if hasNextPage else None

        return {
            "catalogs": convert_decimals(returned_items),
            "pagination": {
                "hasNextPage": hasNextPage,
                "cursor": next_cursor,
                "totalReturned": len(returned_items),
            },
        }
    except ValueError:
        raise
    except Exception as e:
        LOG.error(e)
        raise


@tracer.capture_method
def delete_tm(job_id, owner, force_release=False):
    table = _get_dynamodb_access().table(AGENT_TABLE)
    sharing_table = _get_dynamodb_access().table(SHARING_TABLE)

    try:
        # For non-MCP users, check if user is owner
        if owner != "MCP":
            from utils.authorization import require_owner
            from services.lock_service import (
                get_lock_status,
                force_release_lock as force_lock_release,
            )

            # Verify user is owner
            require_owner(job_id, owner)

            # Check for active locks
            lock_status = get_lock_status(job_id)

            if lock_status.get("locked"):
                lock_holder = lock_status.get("user_id")

                # If lock is held by someone else and force_release is not requested
                if lock_holder != owner and not force_release:
                    LOG.warning(f"Cannot delete {job_id} - locked by {lock_holder}")
                    raise ConflictError(
                        f"Cannot delete threat model while it is locked by {lock_holder}. "
                        "Use force_release=true to override."
                    )

                # Force release the lock if requested
                if lock_holder != owner:
                    LOG.info(f"Force releasing lock for {job_id} before deletion")
                    force_lock_release(job_id, owner)

        # Check if there's an active execution and stop it
        status = check_status(job_id)
        if status.get("state") not in ["COMPLETE", "FAILED", "Not Found"]:
            # There's an active execution, try to stop it
            session_id = status.get("session_id")
            if session_id:
                try:
                    LOG.info(f"Stopping active execution for {job_id} before deletion")
                    # Use override_execution_owner=True to allow owner to stop executions started by others
                    delete_session(
                        job_id, session_id, owner, override_execution_owner=True
                    )
                except Exception as e:
                    LOG.warning(f"Failed to stop execution for {job_id}: {e}")
                    # Continue with deletion even if stop fails

        # Delete associated attack trees before deleting threat model
        try:
            from services.attack_tree_service import (
                delete_attack_trees_for_threat_model,
            )

            LOG.info(f"Deleting attack trees for threat model {job_id}")
            delete_attack_trees_for_threat_model(job_id, owner)
        except Exception as e:
            LOG.warning(f"Error deleting attack trees for {job_id}: {e}")
            # Continue with threat model deletion even if attack tree deletion fails

        key = {"job_id": job_id}
        object_key = fetch_results(job_id).get("item").get("s3_location")
        if not object_key:
            LOG.info(f"Object key not found for job_id: {job_id}")
            raise InternalError()

        # Delete from DynamoDB
        delete_dynamodb_item(table, key, owner)

        # Delete backup if it exists
        try:
            _backup_table().delete_item(Key={"job_id": job_id})
        except Exception as e:
            LOG.warning(f"Error deleting backup for {job_id}: {e}")

        # Delete S3 object
        delete_s3_object(object_key)

        # Clean up sharing records if any exist
        if owner != "MCP":
            try:
                # Query all sharing records for this threat model
                sharing_response = sharing_table.query(
                    KeyConditionExpression="threat_model_id = :tm_id",
                    ExpressionAttributeValues={":tm_id": job_id},
                )

                # Delete all sharing records
                with sharing_table.batch_writer() as batch:
                    for item in sharing_response.get("Items", []):
                        batch.delete_item(
                            Key={
                                "threat_model_id": item["threat_model_id"],
                                "user_id": item["user_id"],
                            }
                        )

                LOG.info(
                    f"Deleted {len(sharing_response.get('Items', []))} sharing records for {job_id}"
                )
            except Exception as e:
                LOG.warning(f"Error cleaning up sharing records: {e}")
                # Continue with deletion even if sharing cleanup fails

        return {"job_id": job_id, "state": "Deleted"}
    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(e)
        raise


@tracer.capture_method
def delete_session(job_id, session_id, owner, override_execution_owner=False):
    agent_table = _get_dynamodb_access().table(AGENT_TABLE)
    state_table = _get_dynamodb_access().table(STATE)

    try:
        # Security validation: query STATE table and verify ownership
        state_response = state_table.get_item(Key={"id": job_id})

        if "Item" not in state_response:
            LOG.warning(f"Job {job_id} not found")
            raise NotFoundError

        state_item = state_response["Item"]

        # Verify session_id and id (job_id) match
        if state_item.get("session_id") != session_id or state_item.get("id") != job_id:
            LOG.warning(f"Session validation failed for job {job_id}")
            raise NotFoundError

        # When override_execution_owner is True (called from delete_tm), verify threat model ownership instead
        if override_execution_owner:
            # Verify the caller is the threat model owner
            tm_owner = state_item.get("owner")
            if tm_owner != owner:
                LOG.warning(
                    f"Authorization failed: {owner} is not the owner of threat model {job_id}"
                )
                raise UnauthorizedError(
                    "You do not have permission to stop this threat modeling session. Only the threat model owner can stop it during deletion."
                )
            LOG.info(
                f"Override enabled: {owner} (threat model owner) stopping execution started by {state_item.get('execution_owner')}"
            )
        else:
            # Normal flow: verify execution_owner matches (only the user who started the execution can stop it)
            execution_owner = state_item.get("execution_owner", state_item.get("owner"))
            if execution_owner != owner:
                LOG.warning(
                    f"Authorization failed: {owner} did not initiate execution of job {job_id}, {execution_owner} did"
                )
                raise UnauthorizedError(
                    "You do not have permission to stop this threat modeling session. Only the user who started the execution can stop it."
                )

        try:
            _stop_threat_model_session(session_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                LOG.warning(f"Session {session_id} not found, proceeding with cleanup")
            else:
                raise

        key = {"job_id": job_id}
        item = fetch_results(job_id).get("item")
        object_key = item.get("s3_location")

        has_backup = "Item" in _backup_table().get_item(Key={"job_id": job_id})

        if not has_backup:
            if not object_key:
                LOG.info(f"Object key not found for job_id: {job_id}")
                raise InternalError()
            delete_dynamodb_item(agent_table, key, owner)
            delete_s3_object(object_key)
            # Also delete sharing records if this was a version job
            parent_id = state_item.get("parent_id")
            if parent_id:
                _delete_sharing_records(job_id)
            # Also delete from state table
            state_table.delete_item(Key={"id": job_id})
            LOG.info(f"State table item deleted for job_id: {job_id}")
            result = {"job_id": job_id, "state": "Deleted"}
            if parent_id:
                result["parent_id"] = parent_id
            return result
        restore(job_id, owner)
        return {"job_id": job_id, "state": "Restored"}
    except Exception as e:
        LOG.error(e)
        raise


@tracer.capture_method
def generate_presigned_url(file_type="image/png", expiration=300):
    key = str(uuid.uuid4())
    try:
        response = _get_s3_access().generate_presigned_put_object(
            bucket_name=ARCHITECTURE_BUCKET,
            object_key=key,
            file_type=file_type,
            expiration=expiration,
        )
    except Exception as e:
        LOG.error(e)
        raise InternalError(e)

    return {"presigned": response, "name": key}


def upload_diagram_directly(base64_data, file_type="image/png"):
    """Upload diagram directly to storage via backend (for Supabase compatibility).

    Supabase signed upload URLs don't support CORS from browsers, so we
    accept base64 data from the frontend and upload server-side.
    """
    import base64
    key = str(uuid.uuid4())
    try:
        binary_data = base64.b64decode(base64_data)
        storage = _get_s3_access()
        storage.put_object(
            bucket_name=ARCHITECTURE_BUCKET,
            object_key=key,
            data=binary_data,
            content_type=file_type,
        )
        LOG.info("Diagram uploaded directly to storage", key=key)
        return {"success": True, "name": key}
    except Exception as e:
        LOG.error(e)
        raise InternalError(f"Failed to upload diagram: {e}")


def extract_threat_model_id_from_s3_location(s3_location: str) -> str:
    """
    Extract threat model ID from S3 location.

    NOTE: This function currently assumes s3_location IS the threat model ID,
    which is INCORRECT. The s3_location is a separate UUID for the S3 object.

    TODO: This needs to be refactored to accept threat_model_id directly
    instead of s3_location. The API should be changed to:
    - Accept threat_model_id as input
    - Look up the threat model record to get s3_location
    - Generate presigned URL for that s3_location

    This would be more efficient (direct get vs scan) and more logical.

    Args:
        s3_location: The S3 key/path (currently incorrectly assumed to be UUID)

    Returns:
        str: The threat model ID (UUID)

    Raises:
        ValueError: If s3_location is empty or not a valid UUID format
        NotFoundError: If the ID cannot be extracted
    """
    if not s3_location or not s3_location.strip():
        raise ValueError("S3 location cannot be empty")

    # S3 location is the UUID itself (INCORRECT ASSUMPTION)
    threat_model_id = s3_location.strip()

    # Validate UUID format
    try:
        uuid.UUID(threat_model_id)
    except (ValueError, AttributeError):
        LOG.warning(f"Invalid UUID format for S3 location: {s3_location}")
        raise NotFoundError(f"Invalid threat model ID format: {s3_location}")

    return threat_model_id


@tracer.capture_method
def generate_presigned_download_url(threat_model_id, user_id=None, expiration=300):
    """
    Generate a presigned URL for downloading a threat model's architecture diagram from S3.

    Args:
        threat_model_id (str): The threat model ID (job_id)
        user_id (str, optional): User ID requesting the presigned URL. If provided, authorization is checked.
        expiration (int, optional): Time in seconds until the presigned URL expires. Defaults to 300.

    Returns:
        str: Presigned URL that can be used to download the object

    Raises:
        UnauthorizedError: If user doesn't have access to the threat model
        NotFoundError: If threat model not found or has no s3_location
        InternalError: If there is an error generating the presigned URL
    """
    # If user_id is provided, check authorization
    if user_id:
        from utils.authorization import require_access

        # Verify user has at least READ_ONLY access
        require_access(threat_model_id, user_id, required_level="READ_ONLY")

    # Look up the threat model to get the s3_location
    try:
        agent_table = _get_dynamodb_access().table(AGENT_TABLE)
        response = agent_table.get_item(Key={"job_id": threat_model_id})

        if "Item" not in response:
            raise NotFoundError(f"Threat model {threat_model_id} not found")

        s3_location = response["Item"].get("s3_location")
        if not s3_location:
            raise NotFoundError(
                f"Threat model {threat_model_id} has no architecture diagram"
            )

    except NotFoundError:
        raise
    except Exception as e:
        LOG.error(f"Error fetching threat model {threat_model_id}: {e}")
        raise InternalError(f"Failed to fetch threat model: {str(e)}")

    # Avoid returning a signed URL that 404s when the object was never uploaded or was removed
    storage = _get_s3_access()
    if hasattr(storage, "object_exists"):
        try:
            if not storage.object_exists(ARCHITECTURE_BUCKET, s3_location):
                raise NotFoundError(
                    "Architecture diagram is missing from storage. "
                    "Upload a diagram again, or fix the stored file reference for this threat model."
                )
        except NotFoundError:
            raise
        except Exception as e:
            LOG.warning(
                "Could not verify architecture object exists before presign; continuing: %s",
                e,
            )

    # Generate presigned URL for the S3 object
    try:
        response = storage.generate_presigned_url(
            "get_object",
            params={"Bucket": ARCHITECTURE_BUCKET, "Key": s3_location},
            expires_in=expiration,
            http_method="GET",
        )
    except Exception as e:
        LOG.error(e)
        raise InternalError(e)

    return response


def _batch_fetch_threat_models(threat_model_ids: list) -> dict:
    """
    Batch fetch threat models from DynamoDB.

    Args:
        threat_model_ids: List of threat model IDs to fetch

    Returns:
        Dict mapping threat_model_id -> threat model item
    """
    if not threat_model_ids:
        return {}

    try:
        # DynamoDB batch_get_item supports up to 100 items per request
        # Split into chunks if needed
        chunk_size = 100
        all_items = {}

        for i in range(0, len(threat_model_ids), chunk_size):
            chunk = threat_model_ids[i : i + chunk_size]

            response = _get_dynamodb_access().batch_get_items(
                {
                    AGENT_TABLE: {
                        "Keys": [{"job_id": tm_id} for tm_id in chunk],
                        "ProjectionExpression": _CATALOG_PROJECTION,
                        "ExpressionAttributeNames": _CATALOG_PROJECTION_NAMES,
                    }
                }
            )

            # Map items by job_id
            for item in response.get("Responses", {}).get(AGENT_TABLE, []):
                all_items[item["job_id"]] = item

            # Handle unprocessed keys (throttling)
            unprocessed = response.get("UnprocessedKeys", {})
            if unprocessed:
                LOG.warning(
                    f"Unprocessed keys in batch_get_item: {len(unprocessed)} items"
                )

        return all_items
    except Exception as e:
        LOG.error(f"Error batch fetching threat models: {e}")
        return {}


def _batch_fetch_sharing_records(threat_model_ids: list, user_id: str) -> dict:
    """
    Batch fetch sharing records from DynamoDB.

    Args:
        threat_model_ids: List of threat model IDs
        user_id: User ID to check sharing for

    Returns:
        Dict mapping threat_model_id -> sharing record (if exists)
    """
    if not threat_model_ids:
        return {}

    try:
        # DynamoDB batch_get_item supports up to 100 items per request
        chunk_size = 100
        all_items = {}

        for i in range(0, len(threat_model_ids), chunk_size):
            chunk = threat_model_ids[i : i + chunk_size]

            response = _get_dynamodb_access().batch_get_items(
                {
                    SHARING_TABLE: {
                        "Keys": [
                            {"threat_model_id": tm_id, "user_id": user_id}
                            for tm_id in chunk
                        ]
                    }
                }
            )

            # Map items by threat_model_id
            for item in response.get("Responses", {}).get(SHARING_TABLE, []):
                all_items[item["threat_model_id"]] = item

        return all_items
    except Exception as e:
        LOG.error(f"Error batch fetching sharing records: {e}")
        return {}


def _check_access_cached(
    threat_model_id: str, user_id: str, threat_models_cache: dict, sharing_cache: dict
) -> dict:
    """
    Check access using pre-fetched cache data.

    Args:
        threat_model_id: Threat model ID to check
        user_id: User ID requesting access
        threat_models_cache: Pre-fetched threat models
        sharing_cache: Pre-fetched sharing records

    Returns:
        Dict with {has_access: bool, access_level: str, is_owner: bool}

    Raises:
        NotFoundError: If threat model not found
    """
    # Check if threat model exists in cache
    if threat_model_id not in threat_models_cache:
        raise NotFoundError(f"Threat model {threat_model_id} not found")

    item = threat_models_cache[threat_model_id]
    owner = item.get("owner")

    # Check if user is the owner
    if owner == user_id:
        return {"has_access": True, "is_owner": True, "access_level": "OWNER"}

    # Check if user is a collaborator (from cache)
    if threat_model_id in sharing_cache:
        return {
            "has_access": True,
            "is_owner": False,
            "access_level": sharing_cache[threat_model_id].get("access_level"),
        }

    # No access
    return {"has_access": False, "is_owner": False, "access_level": None}


def generate_presigned_download_url_with_auth(
    threat_model_id: str, user_id: str, expiration: int = 300
) -> str:
    """
    Generate presigned URL with authorization check.

    This function always performs authorization checks before generating
    the presigned URL. It verifies the user has at least READ_ONLY access
    to the threat model.

    Args:
        threat_model_id: The threat model ID (job_id)
        user_id: User requesting access
        expiration: URL expiration time in seconds (default: 300)

    Returns:
        str: Presigned URL for downloading the architecture diagram

    Raises:
        UnauthorizedError: If user lacks access to the threat model
        NotFoundError: If threat model not found
        InternalError: If presigned URL generation fails
    """
    # Generate presigned URL with authorization
    # The generate_presigned_download_url function will handle both authorization and S3 lookup
    return generate_presigned_download_url(
        threat_model_id, user_id=user_id, expiration=expiration
    )


def generate_presigned_download_urls_batch(
    threat_model_ids: list, user_id: str, expiration: int = 300
) -> list:
    """
    Generate multiple presigned URLs with authorization checks.

    Optimized to use batch DynamoDB reads for better performance.
    Processes requests in parallel for performance. Each threat model is
    processed independently - authorization failures for one threat model do not
    prevent processing of other threat models.

    Args:
        threat_model_ids: List of threat model IDs (job_ids)
        user_id: User requesting access
        expiration: URL expiration time in seconds (default: 300)

    Returns:
        List of dicts with structure:
        {
            "threat_model_id": str,
            "presigned_url": str (if successful),
            "error": str (if failed),
            "success": bool
        }

    Note:
        Results are returned in the same order as input threat_model_ids.
        Partial failures are supported - some items may succeed while others fail.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Batch fetch all threat models and sharing records upfront
    threat_models_cache = _batch_fetch_threat_models(threat_model_ids)
    sharing_cache = _batch_fetch_sharing_records(threat_model_ids, user_id)

    def process_single_threat_model(threat_model_id: str, index: int) -> dict:
        """
        Process a single threat model and return result with index for ordering.
        Uses cached data for authorization and threat model lookup.

        Args:
            threat_model_id: Threat model ID to process
            index: Original index in input list for maintaining order

        Returns:
            dict: Result with index for ordering
        """
        try:
            # Check authorization using cached data
            access_info = _check_access_cached(
                threat_model_id, user_id, threat_models_cache, sharing_cache
            )

            if not access_info["has_access"]:
                raise UnauthorizedError("You do not have access to this threat model")

            # Get s3_location from cached threat model
            if threat_model_id not in threat_models_cache:
                raise NotFoundError(f"Threat model {threat_model_id} not found")

            s3_location = threat_models_cache[threat_model_id].get("s3_location")
            if not s3_location:
                raise NotFoundError(
                    f"Threat model {threat_model_id} has no architecture diagram"
                )

            # Generate presigned URL (fast, no I/O)
            presigned_url = _get_s3_access().generate_presigned_url(
                "get_object",
                params={"Bucket": ARCHITECTURE_BUCKET, "Key": s3_location},
                expires_in=expiration,
                http_method="GET",
            )

            return {
                "index": index,
                "threat_model_id": threat_model_id,
                "presigned_url": presigned_url,
                "success": True,
            }
        except UnauthorizedError as e:
            LOG.warning(f"Authorization failed for {threat_model_id}: {e}")
            return {
                "index": index,
                "threat_model_id": threat_model_id,
                "error": f"Unauthorized: {str(e)}",
                "success": False,
            }
        except NotFoundError as e:
            LOG.warning(f"Not found error for {threat_model_id}: {e}")
            return {
                "index": index,
                "threat_model_id": threat_model_id,
                "error": f"Not Found: {str(e)}",
                "success": False,
            }
        except ValueError as e:
            LOG.warning(f"Validation error for {threat_model_id}: {e}")
            return {
                "index": index,
                "threat_model_id": threat_model_id,
                "error": f"Invalid: {str(e)}",
                "success": False,
            }
        except Exception as e:
            LOG.error(f"Unexpected error processing {threat_model_id}: {e}")
            return {
                "index": index,
                "threat_model_id": threat_model_id,
                "error": f"Internal Error: {str(e)}",
                "success": False,
            }

    # Process all threat models in parallel
    results_with_index = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all tasks with their original index
        future_to_index = {
            executor.submit(process_single_threat_model, tm_id, idx): idx
            for idx, tm_id in enumerate(threat_model_ids)
        }

        # Collect results as they complete
        for future in as_completed(future_to_index):
            try:
                result = future.result()
                results_with_index.append(result)
            except Exception as e:
                # This should not happen as exceptions are caught in process_single_threat_model
                idx = future_to_index[future]
                LOG.error(f"Unexpected error in future for index {idx}: {e}")
                results_with_index.append(
                    {
                        "index": idx,
                        "threat_model_id": threat_model_ids[idx],
                        "error": f"Internal Error: {str(e)}",
                        "success": False,
                    }
                )

    # Sort results by original index to maintain input order
    results_with_index.sort(key=lambda x: x["index"])

    # Remove index from results before returning
    results = []
    for result in results_with_index:
        result_copy = result.copy()
        del result_copy["index"]
        results.append(result_copy)

    return results


def get_dashboard_stats(owner: str) -> dict:
    """
    Get aggregated dashboard stats for all threat models owned by the user,
    plus spaces, documents, and AI security recommendation details.
    """
    agent_table = _get_dynamodb_access().table(AGENT_TABLE)
    owned_items = get_all_by_owner(agent_table, owner)
    
    total_models = len(owned_items)
    total_threats = 0
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    
    recent_models = []
    # Sort by timestamp desc
    sorted_items = sorted(owned_items, key=lambda x: x.get("timestamp", ""), reverse=True)
    
    for item in sorted_items[:5]:
        high_c = 0
        medium_c = 0
        low_c = 0
        threat_list_c = item.get("threat_list")
        if isinstance(threat_list_c, dict):
            threats_c = threat_list_c.get("threats", [])
            if isinstance(threats_c, list):
                for t in threats_c:
                    if isinstance(t, dict):
                        l_c = t.get("likelihood") or "Medium"
                        if l_c == "High":
                            high_c += 1
                        elif l_c == "Medium":
                            medium_c += 1
                        elif l_c == "Low":
                            low_c += 1
        recent_models.append({
            "job_id": item.get("job_id"),
            "title": item.get("title"),
            "timestamp": item.get("timestamp"),
            "state": item.get("state") or "COMPLETE",
            "stats": {
                "high": high_c,
                "medium": medium_c,
                "low": low_c
            }
        })

    top_threats = []

    # STRIDE counts
    stride_counts = {
        "Spoofing": 0,
        "Tampering": 0,
        "Repudiation": 0,
        "Information Disclosure": 0,
        "Denial of Service": 0,
        "Elevation of Privilege": 0
    }

    # PASTA stage counts
    pasta_counts = {
        "Stage 1: Define Objectives": 0,
        "Stage 2: Define Technical Scope": 0,
        "Stage 3: Application Decomposition": 0,
        "Stage 4: Threat Analysis": 0,
        "Stage 5: Vulnerability & Weakness Analysis": 0,
        "Stage 6: Attack Modeling": 0,
        "Stage 7: Risk & Impact Analysis": 0
    }

    # MITRE ATT&CK tactic counts
    mitre_counts = {
        "Reconnaissance": 0,
        "Resource Development": 0,
        "Initial Access": 0,
        "Execution": 0,
        "Persistence": 0,
        "Privilege Escalation": 0,
        "Defense Evasion": 0,
        "Credential Access": 0,
        "Discovery": 0,
        "Lateral Movement": 0,
        "Collection": 0,
        "Command and Control": 0,
        "Exfiltration": 0,
        "Impact": 0
    }

    def _increment_canonical(counts_map, value):
        """Increment the matching canonical bucket for a threat field value.

        Matches case-insensitively so minor casing/whitespace differences from
        the model do not drop the count. No-op when value is missing or unknown.
        """
        if not value:
            return
        if value in counts_map:
            counts_map[value] += 1
            return
        normalized = str(value).strip().lower()
        for canonical in counts_map:
            if canonical.lower() == normalized:
                counts_map[canonical] += 1
                break

    for item in owned_items:
        threat_list = item.get("threat_list")
        if isinstance(threat_list, dict):
            threats = threat_list.get("threats", [])
            if isinstance(threats, list):
                for t in threats:
                    if isinstance(t, dict):
                        total_threats += 1
                        l = t.get("likelihood") or "Medium"
                        if l == "High":
                            high_risk += 1
                        elif l == "Medium":
                            medium_risk += 1
                        elif l == "Low":
                            low_risk += 1

                        # STRIDE / PASTA / MITRE counts
                        sc = t.get("stride_category")
                        _increment_canonical(stride_counts, sc)
                        _increment_canonical(pasta_counts, t.get("pasta_stage"))
                        _increment_canonical(mitre_counts, t.get("mitre_attack"))

                        # Gather Top Threats (up to 5)
                        if len(top_threats) < 5:
                            top_threats.append({
                                "name": t.get("name"),
                                "likelihood": l,
                                "target": t.get("target"),
                                "model_title": item.get("title"),
                                "model_id": item.get("job_id"),
                                "threat_id": t.get("id"),
                                "stride_category": sc,
                                "pasta_stage": t.get("pasta_stage"),
                                "mitre_attack": t.get("mitre_attack")
                            })

    # Get user spaces and recent documents
    spaces_list = []
    recent_documents = []
    try:
        from services.space_service import list_spaces, list_documents
        user_spaces = list_spaces(owner)
        for space in user_spaces:
            spaces_list.append({
                "space_id": space.get("space_id"),
                "name": space.get("name"),
                "description": space.get("description"),
                "created_at": space.get("created_at")
            })
            
            # Fetch documents in space
            try:
                space_docs = list_documents(space.get("space_id"), owner)
                for doc in space_docs:
                    recent_documents.append({
                        "document_id": doc.get("document_id"),
                        "filename": doc.get("filename"),
                        "space_name": space.get("name"),
                        "space_id": space.get("space_id"),
                        "created_at": doc.get("created_at"),
                        "status": doc.get("status")
                    })
            except Exception:
                pass
    except Exception as e:
        LOG.warning(f"Failed to fetch spaces info for dashboard: {e}")

    # Sort documents by created_at desc
    recent_documents.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    recent_documents = recent_documents[:5]
    
    # Sort spaces by created_at desc
    spaces_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    spaces_list = spaces_list[:3]

    # Generate dynamic AI Security Recommendations based on highest STRIDE category
    highest_stride = "Spoofing"
    max_count = -1
    for k, v in stride_counts.items():
        if v > max_count:
            max_count = v
            highest_stride = k

    # Custom advisors/recommendations based on highest stride
    advisories = []
    if highest_stride == "Spoofing" or max_count <= 0:
        advisories = [
            {
                "title": "Enforce Strong Machine-to-Machine Authentication",
                "description": f"Spoofing is currently your highest threat vector ({stride_counts.get('Spoofing', 0)} threats). Consider deploying mutual TLS (mTLS) or OAuth 2.0 Client Credentials with short-lived tokens to verify caller identities.",
                "severity": "High"
            },
            {
                "title": "Validate JWT Issuers and Signatures",
                "description": "Ensure all ingress API endpoints strictly validate JWT tokens, including checking the issuer ('iss'), audience ('aud'), expiration ('exp') claims and verifying signatures using public JWKS endpoints.",
                "severity": "Medium"
            }
        ]
    elif highest_stride == "Tampering":
        advisories = [
            {
                "title": "Implement Payload Validation & Cryptographic Signatures",
                "description": f"Tampering was identified as a primary concern ({stride_counts['Tampering']} threats). Apply strict payload schema validation (Pydantic/FastAPI) and sign sensitive messages transmitted between microservices.",
                "severity": "High"
            },
            {
                "title": "Enable Storage Encryption and Integrity Checks",
                "description": "Enforce database-level encryption at rest, use SSL/TLS connections for all query commands, and compute SHA-256 integrity checksums for sensitive file storage assets.",
                "severity": "High"
            }
        ]
    elif highest_stride == "Information Disclosure":
        advisories = [
            {
                "title": "Apply Sensitive Data Masking and Logging Rules",
                "description": f"Information Disclosure represents a major risk area ({stride_counts['Information Disclosure']} threats). Filter and mask personally identifiable info (PII) or secrets prior to console logging or exception handling.",
                "severity": "High"
            },
            {
                "title": "Implement Strict CORS and Security Headers",
                "description": "Restrict Origin header checks to trusted origins. Ensure strict HTTP response headers are set (X-Content-Type-Options: nosniff, Content-Security-Policy).",
                "severity": "Medium"
            }
        ]
    elif highest_stride == "Denial of Service":
        advisories = [
            {
                "title": "Apply API Rate Limiting and Circuit Breakers",
                "description": f"Denial of Service is your highest threat category ({stride_counts['Denial of Service']} threats). Setup rate limiting at the API Gateway level and configure circuit breakers to avoid resource exhaustion.",
                "severity": "High"
            }
        ]
    else:
        advisories = [
            {
                "title": "Enforce Principal of Least Privilege (PoLP)",
                "description": "Elevation of Privilege or authorization gaps detected. Configure strict Role-Based Access Control (RBAC) and verify authorization claims for every user operation.",
                "severity": "High"
            },
            {
                "title": "Regularly Review and Rotate API Tokens",
                "description": "Protect access tokens, rotate secrets dynamically (e.g. using a secure store), and audit administrative permissions.",
                "severity": "Medium"
            }
        ]

    return {
        "total_models": total_models,
        "total_threats": total_threats,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "recent_models": recent_models,
        "top_threats": top_threats,
        "stride_counts": stride_counts,
        "pasta_counts": pasta_counts,
        "mitre_counts": mitre_counts,
        "spaces": spaces_list,
        "recent_documents": recent_documents,
        "advisories": advisories
    }


