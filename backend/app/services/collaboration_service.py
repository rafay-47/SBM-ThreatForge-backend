from datetime import datetime, timezone
from typing import Any, Dict, List

from utils.powertools_compat import Logger, Tracer
from utils.data_access_factory import get_database_access
from utils.service_contracts import (
    AGENT_STATE_TABLE,
    ARCHITECTURE_BUCKET,
    JOB_STATUS_TABLE,
    LOCKS_TABLE,
    REGION,
    SHARING_TABLE,
)
from exceptions.exceptions import InternalError, NotFoundError, UnauthorizedError
from services.user_directory_service import get_user_profile, list_directory_users

# Environment variables
STATE_TABLE = JOB_STATUS_TABLE
AGENT_TABLE = AGENT_STATE_TABLE
AWS_REGION = REGION

_db_access = None

# Backward-compatible injectable global for older tests.
dynamodb = None


class _LegacyDynamoAccess:
    def __init__(self, dynamodb_resource):
        self._dynamodb_resource = dynamodb_resource

    def table(self, table_name: str):
        return self._dynamodb_resource.Table(table_name)

    def resource(self):
        return self._dynamodb_resource


def _get_db_access():
    global _db_access
    if dynamodb is not None:
        return _LegacyDynamoAccess(dynamodb)

    if _db_access is None:
        _db_access = get_database_access(region_name=AWS_REGION)
    return _db_access


LOG = Logger(serialize_stacktrace=False)
tracer = Tracer()


def convert_decimals(obj):
    """Recursively converts Decimal to float or int in a dictionary."""
    import decimal

    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, decimal.Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    else:
        return obj


@tracer.capture_method
def check_access(threat_model_id: str, user_id: str) -> Dict[str, Any]:
    """
    Check if a user has access to a threat model and what level.

    Args:
        threat_model_id: The threat model ID
        user_id: The user to check

    Returns:
        Dict with {has_access: bool, access_level: str, is_owner: bool}
    """
    try:
        agent_table = _get_db_access().table(AGENT_TABLE)

        # Get the threat model to check ownership
        response = agent_table.get_item(Key={"job_id": threat_model_id})

        if "Item" not in response:
            raise NotFoundError(f"Threat model {threat_model_id} not found")

        item = response["Item"]
        owner = item.get("owner")

        # Check if user is the owner
        if owner == user_id:
            return {"has_access": True, "is_owner": True, "access_level": "OWNER"}

        # Check if user is a collaborator
        sharing_table = _get_db_access().table(SHARING_TABLE)
        share_response = sharing_table.get_item(
            Key={"threat_model_id": threat_model_id, "user_id": user_id}
        )

        if "Item" in share_response:
            return {
                "has_access": True,
                "is_owner": False,
                "access_level": share_response["Item"].get("access_level"),
            }

        # No access
        return {"has_access": False, "is_owner": False, "access_level": None}

    except Exception as e:
        LOG.error(f"Error checking access: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def share_threat_model(
    threat_model_id: str, owner: str, collaborators: List[Dict[str, str]]
) -> Dict:
    """
    Share a threat model with collaborators.

    Args:
        threat_model_id: The threat model to share
        owner: The owner of the threat model
        collaborators: List of {user_id, access_level} dicts

    Returns:
        Dict with sharing status

    Raises:
        UnauthorizedError: If requester is not the owner
        NotFoundError: If threat model doesn't exist
    """
    try:
        # Verify ownership
        access = check_access(threat_model_id, owner)
        if not access.get("is_owner"):
            raise UnauthorizedError("Only the owner can share threat models")

        sharing_table = _get_db_access().table(SHARING_TABLE)
        agent_table = _get_db_access().table(AGENT_TABLE)

        # Add collaborators
        shared_count = 0
        for collab in collaborators:
            user_id = collab.get("user_id")
            access_level = collab.get("access_level", "READ_ONLY")

            # Validate access level
            if access_level not in ["READ_ONLY", "EDIT"]:
                LOG.warning(
                    f"Invalid access level {access_level}, defaulting to READ_ONLY"
                )
                access_level = "READ_ONLY"

            # Add to sharing table
            sharing_table.put_item(
                Item={
                    "threat_model_id": threat_model_id,
                    "user_id": user_id,
                    "access_level": access_level,
                    "shared_by": owner,
                    "shared_at": datetime.now(timezone.utc).isoformat(),
                    "owner": owner,
                }
            )
            shared_count += 1

        # Update state table to mark as shared
        if shared_count > 0:
            agent_table.update_item(
                Key={"job_id": threat_model_id},
                UpdateExpression="SET is_shared = :true",
                ExpressionAttributeValues={":true": True},
            )

        return {
            "success": True,
            "threat_model_id": threat_model_id,
            "shared_count": shared_count,
        }

    except (UnauthorizedError, NotFoundError):
        raise
    except Exception as e:
        LOG.error(f"Error sharing threat model: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def get_collaborators(threat_model_id: str, requester: str) -> List[Dict]:
    """
    Get list of collaborators for a threat model.

    Args:
        threat_model_id: The threat model ID
        requester: The user requesting the list

    Returns:
        List of collaborator dicts with user_id, access_level, shared_at

    Raises:
        UnauthorizedError: If requester doesn't have access
    """
    try:
        # Verify requester has access
        access = check_access(threat_model_id, requester)
        if not access.get("has_access"):
            raise UnauthorizedError("You don't have access to this threat model")

        sharing_table = _get_db_access().table(SHARING_TABLE)

        # Query all collaborators for this threat model
        response = sharing_table.query(
            KeyConditionExpression="threat_model_id = :tm_id",
            ExpressionAttributeValues={":tm_id": threat_model_id},
        )

        collaborators = []
        user_cache = {}  # Cache to avoid duplicate user directory lookups

        for item in response.get("Items", []):
            user_id = item.get("user_id")

            # Look up profile from user directory if not in cache
            if user_id not in user_cache:
                try:
                    profile = get_user_profile(user_id)
                    user_cache[user_id] = {
                        "username": profile.get("username") or user_id,
                        "email": profile.get("email") or None,
                        "name": profile.get("name") or None,
                    }
                except Exception as e:
                    LOG.warning(f"Failed to lookup user {user_id}: {e}")
                    user_cache[user_id] = {
                        "username": user_id,
                        "email": None,
                        "name": None,
                    }

            # Skip the requester from the collaborators list
            if user_id == requester:
                continue

            user_info = user_cache[user_id]
            collaborators.append(
                {
                    "user_id": user_id,
                    "username": user_info["username"],
                    "email": user_info["email"],
                    "name": user_info["name"],
                    "access_level": item.get("access_level"),
                    "shared_at": item.get("shared_at"),
                    "shared_by": item.get("shared_by"),
                }
            )

        return {"collaborators": collaborators}

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(f"Error getting collaborators: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def remove_collaborator(
    threat_model_id: str, owner: str, collaborator_user_id: str
) -> Dict:
    """
    Remove a collaborator's access to a threat model.

    Args:
        threat_model_id: The threat model ID
        owner: The owner of the threat model
        collaborator_user_id: The user to remove

    Returns:
        Dict with removal status

    Raises:
        UnauthorizedError: If requester is not the owner
    """
    try:
        # Verify ownership
        access = check_access(threat_model_id, owner)
        if not access.get("is_owner"):
            raise UnauthorizedError("Only the owner can remove collaborators")

        sharing_table = _get_db_access().table(SHARING_TABLE)

        # Remove from sharing table
        sharing_table.delete_item(
            Key={"threat_model_id": threat_model_id, "user_id": collaborator_user_id}
        )

        # Release any locks held by this user
        from services.lock_service import get_lock_status

        lock_status = get_lock_status(threat_model_id)
        if (
            lock_status.get("locked")
            and lock_status.get("user_id") == collaborator_user_id
        ):
            LOG.info(
                f"Releasing lock held by removed collaborator {collaborator_user_id}"
            )
            lock_table = _get_db_access().table(LOCKS_TABLE)
            lock_table.delete_item(Key={"threat_model_id": threat_model_id})

        # Check if there are any remaining collaborators
        response = sharing_table.query(
            KeyConditionExpression="threat_model_id = :tm_id",
            ExpressionAttributeValues={":tm_id": threat_model_id},
            Select="COUNT",
        )

        # If no more collaborators, update state table
        if response.get("Count", 0) == 0:
            agent_table = _get_db_access().table(AGENT_TABLE)
            agent_table.update_item(
                Key={"job_id": threat_model_id},
                UpdateExpression="SET is_shared = :false",
                ExpressionAttributeValues={":false": False},
            )

        return {
            "success": True,
            "threat_model_id": threat_model_id,
            "removed_user": collaborator_user_id,
        }

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(f"Error removing collaborator: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def update_collaborator_access(
    threat_model_id: str, owner: str, collaborator_user_id: str, new_access_level: str
) -> Dict:
    """
    Update a collaborator's access level.

    Args:
        threat_model_id: The threat model ID
        owner: The owner of the threat model
        collaborator_user_id: The user to update
        new_access_level: "READ_ONLY" or "EDIT"

    Returns:
        Dict with update status

    Raises:
        UnauthorizedError: If requester is not the owner
    """
    try:
        # Verify ownership
        access = check_access(threat_model_id, owner)
        if not access.get("is_owner"):
            raise UnauthorizedError("Only the owner can update collaborator access")

        # Validate access level
        if new_access_level not in ["READ_ONLY", "EDIT"]:
            raise ValueError(f"Invalid access level: {new_access_level}")

        sharing_table = _get_db_access().table(SHARING_TABLE)

        # Update access level
        sharing_table.update_item(
            Key={"threat_model_id": threat_model_id, "user_id": collaborator_user_id},
            UpdateExpression="SET access_level = :level",
            ExpressionAttributeValues={":level": new_access_level},
        )

        # If downgrading to READ_ONLY, release any locks held by this user
        if new_access_level == "READ_ONLY":
            from services.lock_service import get_lock_status

            lock_status = get_lock_status(threat_model_id)
            if (
                lock_status.get("locked")
                and lock_status.get("user_id") == collaborator_user_id
            ):
                LOG.info(
                    f"Releasing lock held by user {collaborator_user_id} (downgraded to READ_ONLY)"
                )
                lock_table = _get_db_access().table(LOCKS_TABLE)
                lock_table.delete_item(Key={"threat_model_id": threat_model_id})

        return {
            "success": True,
            "threat_model_id": threat_model_id,
            "user_id": collaborator_user_id,
            "new_access_level": new_access_level,
        }

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(f"Error updating collaborator access: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def list_cognito_users(
    search_filter: str = None, max_results: int = 100, exclude_user: str = None
) -> Dict:
    """
    List all users from Cognito User Pool.

    Args:
        search_filter: Optional search string to filter users
        max_results: Maximum number of results to return
        exclude_user: Optional user_id to exclude from results (typically the current user)

    Returns:
        Dict with list of user dicts containing username, email, name
    """
    try:
        return list_directory_users(search_filter, max_results, exclude_user)
    except Exception as e:
        LOG.error(f"Error listing users from directory: {e}")
        raise InternalError(str(e))


@tracer.capture_method
def list_users_for_sharing(
    search_filter: str = None, max_results: int = 100, exclude_user: str = None
) -> Dict:
    """Provider-neutral wrapper used by routes and frontend sharing flows."""
    return list_cognito_users(search_filter, max_results, exclude_user)
