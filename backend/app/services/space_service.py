"""Service for Spaces — documents in object storage, indexed via Bedrock KB (AWS) or pgvector (Postgres)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.powertools_compat import Logger, Tracer
from utils.data_access_factory import get_database_access, get_storage_access
from utils.service_contracts import (
    DEPLOYMENT_MODE,
    ENABLE_SPACE_KB_INGESTION,
    KB_DATA_SOURCE_ID,
    KNOWLEDGE_BASE_ID,
    PRESIGNED_URL_EXPIRY,
    REGION,
    SPACE_DOCUMENTS_TABLE,
    SPACE_SHARING_TABLE,
    SPACES_BUCKET,
    SPACES_TABLE,
)
from exceptions.exceptions import InternalError, NotFoundError, UnauthorizedError
from services.user_directory_service import get_user_profile


def _is_pgvector_ingestion_enabled() -> bool:
    try:
        from services.space_pgvector_service import is_pgvector_configured

        return is_pgvector_configured()
    except Exception:
        return False


def _download_space_file(bucket: str, object_key: str) -> bytes:
    storage = _get_storage_access()
    if hasattr(storage, "get_object"):
        return storage.get_object(bucket, object_key)
    return storage.client().get_object(Bucket=bucket, Key=object_key)["Body"].read()

_AWS_REGION = REGION

_db_access = None
_storage_access = None
_bedrock_agent_client = None


def _get_db_access():
    global _db_access
    if _db_access is None:
        _db_access = get_database_access(region_name=_AWS_REGION)
    return _db_access


def _get_storage_access():
    global _storage_access
    if _storage_access is None:
        _storage_access = get_storage_access(region_name=_AWS_REGION)
    return _storage_access


def _get_bedrock_agent_client():
    global _bedrock_agent_client
    if _bedrock_agent_client is not None:
        return _bedrock_agent_client

    if (
        DEPLOYMENT_MODE == "aws"
        and ENABLE_SPACE_KB_INGESTION
        and KNOWLEDGE_BASE_ID
        and KB_DATA_SOURCE_ID
    ):
        import boto3
        _bedrock_agent_client = boto3.client("bedrock-agent", region_name=_AWS_REGION)

    return _bedrock_agent_client

LOG = Logger(serialize_stacktrace=False)
tracer = Tracer()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_kb_ingestion_enabled() -> bool:
    bedrock_client = _get_bedrock_agent_client()
    return (
        bedrock_client is not None
        and bool(KNOWLEDGE_BASE_ID)
        and bool(KB_DATA_SOURCE_ID)
    )


def _any_ingestion_enabled() -> bool:
    """True when Bedrock KB or pgvector pipeline will index uploads."""
    return _is_kb_ingestion_enabled() or _is_pgvector_ingestion_enabled()


def _trigger_kb_ingestion(reason: str, space_id: str, document_id: Optional[str] = None) -> bool:
    """Start a KB ingestion job when integration is enabled."""
    bedrock_client = _get_bedrock_agent_client()
    if not _is_kb_ingestion_enabled():
        LOG.info(
            "KB ingestion skipped",
            reason=reason,
            space_id=space_id,
            document_id=document_id,
        )
        return False

    try:
        bedrock_client.start_ingestion_job(
            knowledgeBaseId=KNOWLEDGE_BASE_ID,
            dataSourceId=KB_DATA_SOURCE_ID,
        )
        LOG.debug(
            "KB ingestion triggered",
            reason=reason,
            space_id=space_id,
            document_id=document_id,
        )
        return True
    except Exception as e:
        LOG.warning(
            "Failed to start KB ingestion job",
            reason=reason,
            space_id=space_id,
            document_id=document_id,
            error=str(e),
        )
        return False


def _check_space_owner(space_id: str, user_id: str) -> Dict[str, Any]:
    """Return space item if user is owner, else raise UnauthorizedError."""
    table = _get_db_access().table(SPACES_TABLE)
    response = table.get_item(Key={"space_id": space_id})
    if "Item" not in response:
        raise NotFoundError(f"Space {space_id} not found")
    item = response["Item"]
    if item.get("owner") != user_id:
        raise UnauthorizedError("Only the space owner can perform this operation")
    return item


@tracer.capture_method
def check_space_access(space_id: str, user_id: str) -> Dict[str, Any]:
    """Return access info for user on space. Raises NotFoundError / UnauthorizedError."""
    table = _get_db_access().table(SPACES_TABLE)
    response = table.get_item(Key={"space_id": space_id})
    if "Item" not in response:
        raise NotFoundError(f"Space {space_id} not found")
    item = response["Item"]

    if item.get("owner") == user_id:
        return {"has_access": True, "is_owner": True, "access_level": "OWNER"}

    sharing_table = _get_db_access().table(SPACE_SHARING_TABLE)
    share_resp = sharing_table.get_item(Key={"space_id": space_id, "user_id": user_id})
    if "Item" in share_resp:
        return {
            "has_access": True,
            "is_owner": False,
            "access_level": share_resp["Item"].get("access_level", "READ_ONLY"),
        }

    raise UnauthorizedError("You do not have access to this space")


@tracer.capture_method
def create_space(owner: str, name: str, description: str = "") -> Dict[str, Any]:
    table = _get_db_access().table(SPACES_TABLE)
    space_id = str(uuid.uuid4())
    now = _now()
    item = {
        "space_id": space_id,
        "owner": owner,
        "name": name,
        "description": description,
        "created_at": now,
        "updated_at": now,
    }
    table.put_item(Item=item)
    LOG.debug("Space created", space_id=space_id, owner=owner)
    return item


@tracer.capture_method
def get_space(space_id: str, user_id: str) -> Dict[str, Any]:
    access = check_space_access(space_id, user_id)
    table = _get_db_access().table(SPACES_TABLE)
    response = table.get_item(Key={"space_id": space_id})
    item = dict(response["Item"])
    item["is_owner"] = access.get("is_owner", False)
    return item


@tracer.capture_method
def list_spaces(user_id: str) -> List[Dict[str, Any]]:
    """Return all spaces owned by or shared with user_id."""
    spaces_table = _get_db_access().table(SPACES_TABLE)
    sharing_table = _get_db_access().table(SPACE_SHARING_TABLE)

    # Owned spaces — scan with filter (no GSI needed for MVP)
    owned_resp = spaces_table.scan(
        FilterExpression="#o = :uid",
        ExpressionAttributeNames={"#o": "owner"},
        ExpressionAttributeValues={":uid": user_id},
    )
    owned = owned_resp.get("Items", [])
    owned_ids = {s["space_id"] for s in owned}

    # Shared spaces — query sharing table by user_id GSI
    try:
        shared_resp = sharing_table.query(
            KeyConditionExpression="user_id = :uid",
            ExpressionAttributeValues={":uid": user_id},
        )
        shared_space_ids = [
            item["space_id"]
            for item in shared_resp.get("Items", [])
            if item["space_id"] not in owned_ids
        ]
        shared_spaces = []
        for sid in shared_space_ids:
            r = spaces_table.get_item(Key={"space_id": sid})
            if "Item" in r:
                shared_spaces.append(r["Item"])
    except Exception:
        shared_spaces = []

    return owned + shared_spaces


@tracer.capture_method
def update_space(
    space_id: str, user_id: str, name: Optional[str], description: Optional[str]
) -> Dict[str, Any]:
    _check_space_owner(space_id, user_id)
    table = _get_db_access().table(SPACES_TABLE)
    updates = {"updated_at": _now()}
    if name is not None:
        updates["name"] = name
    if description is not None:
        updates["description"] = description

    update_expr = "SET " + ", ".join(f"#{k} = :{k}" for k in updates)
    expr_names = {f"#{k}": k for k in updates}
    expr_values = {f":{k}": v for k, v in updates.items()}

    response = table.update_item(
        Key={"space_id": space_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
        ReturnValues="ALL_NEW",
    )
    return response["Attributes"]


@tracer.capture_method
def delete_space(space_id: str, user_id: str) -> None:
    _check_space_owner(space_id, user_id)
    table = _get_db_access().table(SPACES_TABLE)
    table.delete_item(Key={"space_id": space_id})
    LOG.debug("Space deleted", space_id=space_id)


@tracer.capture_method
def generate_document_upload_url(
    space_id: str, user_id: str, filename: str, file_type: str
) -> Dict[str, Any]:
    """Generate a presigned storage PUT URL for a space document."""
    _check_space_owner(space_id, user_id)
    document_id = str(uuid.uuid4())
    ext = filename.rsplit(".", 1)[-1] if "." in filename else "bin"
    storage_key = f"spaces/{space_id}/{document_id}.{ext}"

    storage = _get_storage_access()
    presigned_url = storage.generate_presigned_put_object(
        SPACES_BUCKET, storage_key, file_type, PRESIGNED_URL_EXPIRY
    )
    return {
        "document_id": document_id,
        "presigned_url": presigned_url,
        "s3_key": storage_key,
    }


@tracer.capture_method
def confirm_document_upload(
    space_id: str, user_id: str, document_id: str, s3_key: str, filename: str
) -> Dict[str, Any]:
    """Record document in DDB, write KB metadata sidecar, trigger KB ingestion."""
    _check_space_owner(space_id, user_id)
    now = _now()
    initial_status = "INGESTING" if _any_ingestion_enabled() else "READY"
    item = {
        "space_id": space_id,
        "document_id": document_id,
        "filename": filename,
        "s3_key": s3_key,
        "status": initial_status,
        "created_at": now,
        "updated_at": now,
    }
    docs_table = _get_db_access().table(SPACE_DOCUMENTS_TABLE)
    docs_table.put_item(Item=item)

    # Write metadata sidecar for Bedrock KB filtering (AWS)
    metadata_key = f"{s3_key}.metadata.json"
    import json

    metadata = {"metadataAttributes": {"space_id": space_id}}
    try:
        storage = _get_storage_access()
        if DEPLOYMENT_MODE == "aws":
            storage.client().put_object(
                Bucket=SPACES_BUCKET,
                Key=metadata_key,
                Body=json.dumps(metadata),
                ContentType="application/json",
            )
        else:
            storage.put_object(SPACES_BUCKET, metadata_key, json.dumps(metadata).encode(), "application/json")
    except Exception as e:
        LOG.warning("Failed to write KB metadata sidecar", error=str(e), s3_key=s3_key)

    _trigger_kb_ingestion("upload", space_id=space_id, document_id=document_id)

    if _is_pgvector_ingestion_enabled():
        from services.space_pgvector_service import ingest_space_document

        try:
            raw = _download_space_file(SPACES_BUCKET, s3_key)
            ok, _msg = ingest_space_document(
                space_id=space_id,
                document_id=document_id,
                filename=filename,
                file_bytes=raw,
                uploaded_by=user_id,
            )
            final_status = "READY" if ok else "FAILED"
        except Exception as e:
            LOG.warning(
                "Pgvector ingest failed",
                space_id=space_id,
                document_id=document_id,
                error=str(e),
            )
            final_status = "FAILED"
        now = _now()
        docs_table.update_item(
            Key={"space_id": space_id, "document_id": document_id},
            UpdateExpression="SET #s = :s, updated_at = :u",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": final_status, ":u": now},
        )
        item["status"] = final_status
        item["updated_at"] = now

    return item


@tracer.capture_method
def list_documents(space_id: str, user_id: str) -> List[Dict[str, Any]]:
    check_space_access(space_id, user_id)
    docs_table = _get_db_access().table(SPACE_DOCUMENTS_TABLE)
    response = docs_table.query(
        KeyConditionExpression="space_id = :sid",
        ExpressionAttributeValues={":sid": space_id},
    )
    items = response.get("Items", [])

    # Resolve INGESTING status against completed KB ingestion jobs
    ingesting = [d for d in items if d.get("status") == "INGESTING"]
    if ingesting:
        if _is_kb_ingestion_enabled():
            try:
                jobs_resp = _get_bedrock_agent_client().list_ingestion_jobs(
                    knowledgeBaseId=KNOWLEDGE_BASE_ID,
                    dataSourceId=KB_DATA_SOURCE_ID,
                    filters=[
                        {
                            "attribute": "STATUS",
                            "operator": "EQ",
                            "values": ["COMPLETE"],
                        }
                    ],
                    sortBy={"attribute": "STARTED_AT", "order": "DESCENDING"},
                    maxResults=1,
                )
                summaries = jobs_resp.get("ingestionJobSummaries", [])
                if summaries:
                    last_complete_at = summaries[0].get("updatedAt")  # datetime
                    if last_complete_at is not None:
                        if last_complete_at.tzinfo is None:
                            last_complete_at = last_complete_at.replace(
                                tzinfo=timezone.utc
                            )
                        now = _now()
                        for doc in ingesting:
                            doc_created = doc.get("created_at", "")
                            try:
                                doc_dt = datetime.fromisoformat(doc_created)
                                if doc_dt.tzinfo is None:
                                    doc_dt = doc_dt.replace(tzinfo=timezone.utc)
                                if doc_dt <= last_complete_at:
                                    docs_table.update_item(
                                        Key={
                                            "space_id": space_id,
                                            "document_id": doc["document_id"],
                                        },
                                        UpdateExpression="SET #s = :s, updated_at = :u",
                                        ExpressionAttributeNames={"#s": "status"},
                                        ExpressionAttributeValues={
                                            ":s": "READY",
                                            ":u": now,
                                        },
                                    )
                                    doc["status"] = "READY"
                            except (ValueError, TypeError):
                                pass
            except Exception as e:
                LOG.warning("Failed to resolve ingestion status", error=str(e))
        else:
            now = _now()
            for doc in ingesting:
                docs_table.update_item(
                    Key={
                        "space_id": space_id,
                        "document_id": doc["document_id"],
                    },
                    UpdateExpression="SET #s = :s, updated_at = :u",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={
                        ":s": "READY",
                        ":u": now,
                    },
                )
                doc["status"] = "READY"

    return items


@tracer.capture_method
def delete_document(space_id: str, user_id: str, document_id: str) -> None:
    _check_space_owner(space_id, user_id)
    docs_table = _get_db_access().table(SPACE_DOCUMENTS_TABLE)
    resp = docs_table.get_item(Key={"space_id": space_id, "document_id": document_id})
    if "Item" not in resp:
        raise NotFoundError(f"Document {document_id} not found in space {space_id}")
    item = resp["Item"]
    s3_key = item.get("s3_key")

    # Delete from storage + metadata sidecar
    if s3_key:
        try:
            storage = _get_storage_access()
            storage.delete_object(SPACES_BUCKET, s3_key)
            storage.delete_object(SPACES_BUCKET, f"{s3_key}.metadata.json")
        except Exception as e:
            LOG.warning("Storage delete failed", error=str(e), s3_key=s3_key)

    if _is_pgvector_ingestion_enabled():
        try:
            from services.space_pgvector_service import delete_chunks_for_document

            delete_chunks_for_document(space_id, document_id)
        except Exception as e:
            LOG.warning(
                "Pgvector chunk delete failed",
                space_id=space_id,
                document_id=document_id,
                error=str(e),
            )

    docs_table.delete_item(Key={"space_id": space_id, "document_id": document_id})

    # Re-trigger ingestion to sync KB when enabled.
    _trigger_kb_ingestion("delete", space_id=space_id, document_id=document_id)


@tracer.capture_method
def share_space(space_id: str, owner: str, user_ids: List[str]) -> List[Dict[str, Any]]:
    """Grant READ_ONLY access to a list of users."""
    _check_space_owner(space_id, owner)
    sharing_table = _get_db_access().table(SPACE_SHARING_TABLE)
    now = _now()
    results = []
    for uid in user_ids:
        if uid == owner:
            continue
        item = {
            "space_id": space_id,
            "user_id": uid,
            "access_level": "READ_ONLY",
            "granted_at": now,
        }
        sharing_table.put_item(Item=item)
        results.append(item)
    return results


@tracer.capture_method
def get_space_sharing(space_id: str, user_id: str) -> List[Dict[str, Any]]:
    _check_space_owner(space_id, user_id)
    sharing_table = _get_db_access().table(SPACE_SHARING_TABLE)
    response = sharing_table.query(
        KeyConditionExpression="space_id = :sid",
        ExpressionAttributeValues={":sid": space_id},
    )
    items = response.get("Items", [])

    for item in items:
        uid = item.get("user_id", "")
        try:
            profile = get_user_profile(uid)
            item["email"] = profile.get("email", "")
            item["name"] = profile.get("name", "")
            item["username"] = profile.get("username", uid)
        except Exception as e:
            LOG.warning("Failed to lookup user", user_id=uid, error=str(e))

    return items


@tracer.capture_method
def remove_space_sharing(space_id: str, owner: str, target_user_id: str) -> None:
    _check_space_owner(space_id, owner)
    sharing_table = _get_db_access().table(SPACE_SHARING_TABLE)
    sharing_table.delete_item(Key={"space_id": space_id, "user_id": target_user_id})
