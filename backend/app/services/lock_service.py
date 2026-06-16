"""
Lock service for threat model collaboration.

This module provides session locking functionality to prevent concurrent
modifications to threat models. It implements a heartbeat-based locking
mechanism with automatic stale lock detection and expiration.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from utils.powertools_compat import Logger, Tracer
from utils.data_access_factory import get_database_access
from utils.service_contracts import (
    AGENT_STATE_TABLE,
    DATABASE_PROVIDER,
    LOCKS_TABLE,
    REGION,
)
from exceptions.exceptions import InternalError, NotFoundError, UnauthorizedError
from services.user_directory_service import get_user_profile

# Environment variables
LOCK_TABLE = LOCKS_TABLE
AGENT_TABLE = AGENT_STATE_TABLE
AWS_REGION = REGION

# Constants
LOCK_EXPIRATION_SECONDS = 180  # 3 minutes
STALE_LOCK_THRESHOLD = 180  # 3 minutes in seconds

_db_access = None


def _get_db_access():
    global _db_access
    if _db_access is None:
        _db_access = get_database_access(region_name=AWS_REGION)
    return _db_access


LOG = Logger(serialize_stacktrace=False)
tracer = Tracer()


def _pg_locks() -> bool:
    """Postgres locks table (001_initial_schema.sql) uses token + expires_at, not DynamoDB names."""
    return (DATABASE_PROVIDER or "").strip().lower() == "supabase"


def _to_unix(ts) -> int:
    """Coerce ISO timestamp or numeric to unix seconds."""
    if ts is None:
        return 0
    if isinstance(ts, (int, float)):
        return int(ts)
    if isinstance(ts, str):
        try:
            s = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except (ValueError, TypeError):
            return 0
    return 0


def _lock_expiry_unix(item: dict) -> int:
    """Absolute expiry time for the lock (unix seconds)."""
    if item.get("ttl") is not None:
        try:
            return int(item["ttl"])
        except (TypeError, ValueError):
            pass
    if item.get("expires_at") is not None:
        return _to_unix(item["expires_at"])
    lt = item.get("lock_timestamp")
    if lt is not None:
        try:
            return int(lt) + LOCK_EXPIRATION_SECONDS
        except (TypeError, ValueError):
            pass
    return 0


def _lock_timestamp_for_api(item: dict) -> int:
    """lock_timestamp field returned to clients (approximate last heartbeat)."""
    if item.get("lock_timestamp") is not None:
        try:
            return int(item["lock_timestamp"])
        except (TypeError, ValueError):
            pass
    exp = _lock_expiry_unix(item)
    return max(0, exp - LOCK_EXPIRATION_SECONDS) if exp else 0


def _lock_token_str(item: dict) -> str:
    return str(item.get("lock_token") or item.get("token") or "")


def _lock_is_stale(item: dict, current_timestamp: int) -> bool:
    exp = _lock_expiry_unix(item)
    if exp > 0:
        return current_timestamp > exp
    lt = item.get("lock_timestamp")
    if lt is not None:
        try:
            return current_timestamp - int(lt) > STALE_LOCK_THRESHOLD
        except (TypeError, ValueError):
            pass
    return True


def get_username_from_cognito(user_id: str) -> str:
    """
    Look up username from configured user directory by user_id.

    Args:
        user_id: The UUID (sub) of the user

    Returns:
        Username or user_id if lookup fails
    """
    try:
        profile = get_user_profile(user_id)
        return profile.get("username") or user_id
    except Exception as e:
        LOG.warning(f"Failed to lookup username for {user_id}: {e}")
        return user_id


@tracer.capture_method
def acquire_lock(threat_model_id: str, user_id: str) -> Dict[str, Any]:
    """
    Attempt to acquire an edit lock on a threat model.

    Args:
        threat_model_id: The threat model to lock
        user_id: The user requesting the lock

    Returns:
        Dict with {success: bool, lock_token: str, message: str}
        If lock held by another user: {success: False, held_by: str, since: timestamp}

    Logic:
        1. Check if lock exists
        2. If exists, check if timestamp > 15 minutes old
        3. If stale, delete and proceed
        4. If fresh and different user, return conflict
        5. If no lock or same user, create/update lock with new token and timestamp
    """
    lock_table = _get_db_access().table(LOCK_TABLE)
    agent_table = _get_db_access().table(AGENT_TABLE)

    try:
        # Verify threat model exists
        tm_response = agent_table.get_item(Key={"job_id": threat_model_id})
        if "Item" not in tm_response:
            LOG.warning(f"Threat model {threat_model_id} not found")
            raise NotFoundError(f"Threat model {threat_model_id} not found")

        # Check if user has EDIT access
        from services.collaboration_service import check_access

        access_info = check_access(threat_model_id, user_id)

        if not access_info.get("has_access"):
            LOG.warning(f"User {user_id} does not have access to {threat_model_id}")
            raise UnauthorizedError("You do not have access to this threat model")

        # Only owners and users with EDIT access can acquire locks
        if (
            not access_info.get("is_owner")
            and access_info.get("access_level") != "EDIT"
        ):
            LOG.warning(
                f"User {user_id} has READ_ONLY access to {threat_model_id}, cannot acquire lock"
            )
            raise UnauthorizedError("You need EDIT access to acquire a lock")

        # Check for existing lock
        response = lock_table.get_item(Key={"threat_model_id": threat_model_id})

        current_timestamp = int(time.time())

        if "Item" in response:
            existing_lock = response["Item"]
            lock_user_id = existing_lock.get("user_id")

            # Check if lock is stale (expired or older than threshold)
            if _lock_is_stale(existing_lock, current_timestamp):
                LOG.info(f"Stale lock detected for {threat_model_id}, auto-releasing")
                # Delete stale lock
                lock_table.delete_item(Key={"threat_model_id": threat_model_id})
            elif lock_user_id == user_id:
                # Same user re-acquiring lock (e.g., after page refresh)
                # Allow them to get a new lock token and refresh the timestamp
                LOG.info(
                    f"User {user_id} re-acquiring their own lock for {threat_model_id}"
                )
                # Proceed to create new lock with new token (will overwrite existing)
            elif lock_user_id != user_id:
                # Lock is fresh and held by another user
                username = get_username_from_cognito(lock_user_id)
                LOG.info(
                    f"Lock for {threat_model_id} held by {lock_user_id} ({username})"
                )
                return {
                    "success": False,
                    "held_by": lock_user_id,
                    "username": username,
                    "since": existing_lock.get("acquired_at"),
                    "lock_timestamp": _lock_timestamp_for_api(existing_lock),
                    "message": f"Threat model is currently locked by {username}",
                }

        # Create or update lock
        lock_token = str(uuid.uuid4())
        acquired_at = datetime.now(timezone.utc).isoformat()
        ttl = current_timestamp + LOCK_EXPIRATION_SECONDS

        if _pg_locks():
            expires_at = datetime.fromtimestamp(ttl, tz=timezone.utc).isoformat()
            lock_table.put_item(
                Item={
                    "threat_model_id": threat_model_id,
                    "user_id": user_id,
                    "token": lock_token,
                    "acquired_at": acquired_at,
                    "expires_at": expires_at,
                }
            )
        else:
            lock_table.put_item(
                Item={
                    "threat_model_id": threat_model_id,
                    "user_id": user_id,
                    "lock_token": lock_token,
                    "lock_timestamp": current_timestamp,
                    "acquired_at": acquired_at,
                    "ttl": ttl,
                }
            )

        LOG.info(f"Lock acquired for {threat_model_id} by {user_id}")
        return {
            "success": True,
            "lock_token": lock_token,
            "acquired_at": acquired_at,
            "expires_at": int(ttl),
            "message": "Lock acquired successfully",
        }

    except (NotFoundError, UnauthorizedError):
        raise
    except Exception as e:
        LOG.error(f"Error acquiring lock: {e}")
        raise InternalError(f"Failed to acquire lock: {str(e)}")


@tracer.capture_method
def refresh_lock(threat_model_id: str, user_id: str, lock_token: str) -> Dict[str, Any]:
    """
    Refresh a lock's timestamp (heartbeat).

    Args:
        threat_model_id: The threat model ID
        user_id: The user holding the lock
        lock_token: The lock token to validate

    Returns:
        Dict with {success: bool, message: str}

    Logic:
        1. Get current lock
        2. Verify user_id and lock_token match
        3. Update lock_timestamp to current time
        4. Update TTL to lock_timestamp + 900
    """
    lock_table = _get_db_access().table(LOCK_TABLE)

    try:
        # Get current lock
        response = lock_table.get_item(Key={"threat_model_id": threat_model_id})

        if "Item" not in response:
            LOG.warning(f"No lock found for threat model {threat_model_id}")
            return {
                "success": False,
                "message": "Lock not found",
                "status_code": 410,  # Gone
            }

        existing_lock = response["Item"]

        # Verify user_id and lock_token match
        if existing_lock.get("user_id") != user_id:
            LOG.warning(f"Lock for {threat_model_id} held by different user")
            return {
                "success": False,
                "message": "Lock is held by another user",
                "held_by": existing_lock.get("user_id"),
                "status_code": 410,  # Gone
            }

        if _lock_token_str(existing_lock) != lock_token:
            LOG.warning(f"Invalid lock token for {threat_model_id}")
            return {
                "success": False,
                "message": "Invalid lock token",
                "status_code": 410,  # Gone
            }

        # Update lock timestamp and TTL
        current_timestamp = int(time.time())
        ttl = current_timestamp + LOCK_EXPIRATION_SECONDS

        if _pg_locks():
            expires_at = datetime.fromtimestamp(ttl, tz=timezone.utc).isoformat()
            lock_table.update_item(
                Key={"threat_model_id": threat_model_id},
                UpdateExpression="SET expires_at = :exp",
                ExpressionAttributeValues={":exp": expires_at},
            )
        else:
            lock_table.update_item(
                Key={"threat_model_id": threat_model_id},
                UpdateExpression="SET lock_timestamp = :timestamp, #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={":timestamp": current_timestamp, ":ttl": ttl},
            )

        LOG.info(f"Lock refreshed for {threat_model_id} by {user_id}")
        return {
            "success": True,
            "message": "Lock refreshed successfully",
            "expires_at": int(ttl),
        }

    except Exception as e:
        LOG.error(f"Error refreshing lock: {e}")
        raise InternalError(f"Failed to refresh lock: {str(e)}")


@tracer.capture_method
def release_lock(threat_model_id: str, user_id: str, lock_token: str) -> Dict[str, Any]:
    """
    Explicitly release a lock (graceful release).

    Args:
        threat_model_id: The threat model ID
        user_id: The user holding the lock
        lock_token: The lock token to validate (can be None for cleanup)

    Returns:
        Dict with {success: bool, message: str}

    Logic:
        1. Verify user_id and lock_token match
        2. Delete lock record
    """
    lock_table = _get_db_access().table(LOCK_TABLE)

    try:
        # Get current lock to verify ownership
        response = lock_table.get_item(Key={"threat_model_id": threat_model_id})

        if "Item" not in response:
            LOG.info(f"No lock found for threat model {threat_model_id}")
            return {"success": True, "message": "No lock to release"}

        existing_lock = response["Item"]

        # Verify user_id matches
        if existing_lock.get("user_id") != user_id:
            LOG.warning(
                f"User {user_id} cannot release lock held by {existing_lock.get('user_id')}"
            )
            raise UnauthorizedError("You do not hold this lock")

        # If lock_token is provided, verify it matches
        if lock_token and _lock_token_str(existing_lock) != lock_token:
            LOG.warning(f"Invalid lock token for {threat_model_id}")
            raise UnauthorizedError("Invalid lock token")

        # Delete lock
        lock_table.delete_item(Key={"threat_model_id": threat_model_id})

        LOG.info(f"Lock released for {threat_model_id} by {user_id}")
        return {"success": True, "message": "Lock released successfully"}

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(f"Error releasing lock: {e}")
        raise InternalError(f"Failed to release lock: {str(e)}")


@tracer.capture_method
def get_lock_status(threat_model_id: str) -> Dict[str, Any]:
    """
    Get current lock status for a threat model.

    Args:
        threat_model_id: The threat model ID

    Returns:
        Dict with {locked: bool, user_id: str, since: timestamp, expires_at: timestamp}
        If not locked: {locked: False}
    """
    lock_table = _get_db_access().table(LOCK_TABLE)

    try:
        response = lock_table.get_item(Key={"threat_model_id": threat_model_id})

        if "Item" not in response:
            return {"locked": False, "message": "No active lock"}

        lock = response["Item"]
        current_timestamp = int(time.time())

        # Check if lock is stale
        if _lock_is_stale(lock, current_timestamp):
            LOG.info(f"Stale lock detected for {threat_model_id}")
            return {"locked": False, "message": "Lock is stale", "stale": True}

        user_id = lock.get("user_id")
        username = get_username_from_cognito(user_id)

        ttl_out = _lock_expiry_unix(lock)
        if ttl_out <= 0 and lock.get("ttl") is not None:
            try:
                ttl_out = int(lock["ttl"])
            except (TypeError, ValueError):
                ttl_out = None

        return {
            "locked": True,
            "user_id": user_id,
            "username": username,
            "lock_token": _lock_token_str(lock),
            "since": lock.get("acquired_at"),
            "lock_timestamp": _lock_timestamp_for_api(lock),
            "expires_at": ttl_out,
            "message": f"Locked by {username}",
        }

    except Exception as e:
        LOG.error(f"Error getting lock status: {e}")
        raise InternalError(f"Failed to get lock status: {str(e)}")


@tracer.capture_method
def force_release_lock(threat_model_id: str, owner: str) -> Dict[str, Any]:
    """
    Force release a lock (owner only).

    Args:
        threat_model_id: The threat model ID
        owner: The owner requesting force release

    Returns:
        Dict with {success: bool, message: str}

    Raises:
        UnauthorizedError: If requester is not the owner
    """
    from services.collaboration_service import check_access

    lock_table = _get_db_access().table(LOCK_TABLE)

    try:
        # Verify requester is owner
        access_info = check_access(threat_model_id, owner)
        if not access_info["is_owner"]:
            LOG.warning(
                f"User {owner} is not the owner of threat model {threat_model_id}"
            )
            raise UnauthorizedError("Only the owner can force release a lock")

        # Check if lock exists
        response = lock_table.get_item(Key={"threat_model_id": threat_model_id})

        if "Item" not in response:
            LOG.info(f"No lock found for threat model {threat_model_id}")
            return {"success": True, "message": "No lock to release"}

        existing_lock = response["Item"]
        previous_holder = existing_lock.get("user_id")

        # Delete lock
        lock_table.delete_item(Key={"threat_model_id": threat_model_id})

        LOG.info(
            f"Lock force released for {threat_model_id} by owner {owner}, was held by {previous_holder}"
        )
        return {
            "success": True,
            "message": "Lock force released successfully",
            "previous_holder": previous_holder,
        }

    except UnauthorizedError:
        raise
    except Exception as e:
        LOG.error(f"Error force releasing lock: {e}")
        raise InternalError(f"Failed to force release lock: {str(e)}")
