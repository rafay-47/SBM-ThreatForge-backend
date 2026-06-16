"""Unit tests for lock_service.py."""

import sys
from pathlib import Path
from decimal import Decimal
from unittest.mock import Mock, patch

import pytest

# Add backend/app to path for imports
backend_path = str(Path(__file__).parent.parent.parent.parent / "backend" / "app")
sys.path.insert(0, backend_path)

import services.lock_service as lock_service
from exceptions.exceptions import NotFoundError, UnauthorizedError


def _build_db_access(lock_table=None, agent_table=None):
    lock_table = lock_table or Mock()
    agent_table = agent_table or Mock()
    db_access = Mock()

    def _table(name):
        if name == lock_service.LOCK_TABLE:
            return lock_table
        if name == lock_service.AGENT_TABLE:
            return agent_table
        return lock_table

    db_access.table.side_effect = _table
    return db_access


class TestGetUsernameFromCognito:
    @patch("services.lock_service.get_user_profile")
    def test_returns_username_for_valid_user_id(self, mock_get_user_profile):
        mock_get_user_profile.return_value = {"username": "testuser"}

        result = lock_service.get_username_from_cognito("user-123")

        assert result == "testuser"
        mock_get_user_profile.assert_called_once_with("user-123")

    @patch("services.lock_service.get_user_profile")
    def test_returns_user_id_if_profile_missing_username(self, mock_get_user_profile):
        mock_get_user_profile.return_value = {"email": "a@example.com"}

        result = lock_service.get_username_from_cognito("user-123")

        assert result == "user-123"

    @patch("services.lock_service.get_user_profile")
    def test_handles_directory_errors_gracefully(self, mock_get_user_profile):
        mock_get_user_profile.side_effect = Exception("directory error")

        result = lock_service.get_username_from_cognito("user-123")

        assert result == "user-123"


class TestAcquireLock:
    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_successfully_acquires_lock_on_available_resource(
        self, mock_get_db_access, mock_check_access, _mock_time
    ):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {"Item": {"job_id": "tm-1", "owner": "u1"}}
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {}

        result = lock_service.acquire_lock("tm-1", "u1")

        assert result["success"] is True
        assert result["expires_at"] == 1704067200 + lock_service.LOCK_EXPIRATION_SECONDS
        lock_table.put_item.assert_called_once()

    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.lock_service.get_username_from_cognito", return_value="otheruser")
    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_returns_conflict_when_lock_held_by_another_user(
        self,
        mock_get_db_access,
        mock_check_access,
        _mock_get_username,
        _mock_time,
    ):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {"Item": {"job_id": "tm-1", "owner": "u1"}}
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u2",
                "lock_token": "tok",
                "lock_timestamp": 1704067140,
                "acquired_at": "2024-01-01T00:00:00Z",
            }
        }

        result = lock_service.acquire_lock("tm-1", "u1")

        assert result["success"] is False
        assert result["held_by"] == "u2"
        assert result["username"] == "otheruser"
        lock_table.put_item.assert_not_called()

    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_user_can_reacquire_their_own_lock(
        self, mock_get_db_access, mock_check_access, _mock_time
    ):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {"Item": {"job_id": "tm-1", "owner": "u1"}}
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u1",
                "lock_token": "old",
                "lock_timestamp": 1704067140,
            }
        }

        result = lock_service.acquire_lock("tm-1", "u1")

        assert result["success"] is True
        assert result["lock_token"] != "old"
        lock_table.put_item.assert_called_once()

    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_stale_lock_is_auto_released_and_new_lock_acquired(
        self, mock_get_db_access, mock_check_access, _mock_time
    ):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {"Item": {"job_id": "tm-1", "owner": "u1"}}
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u2",
                "lock_token": "stale",
                "lock_timestamp": 1704067200 - lock_service.STALE_LOCK_THRESHOLD - 1,
            }
        }

        result = lock_service.acquire_lock("tm-1", "u1")

        assert result["success"] is True
        lock_table.delete_item.assert_called_once_with(Key={"threat_model_id": "tm-1"})
        lock_table.put_item.assert_called_once()

    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_requires_edit_access_level(self, mock_get_db_access, mock_check_access):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {"Item": {"job_id": "tm-1", "owner": "owner"}}
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": False,
            "access_level": "READ_ONLY",
        }

        with pytest.raises(UnauthorizedError):
            lock_service.acquire_lock("tm-1", "u1")

    @patch("services.lock_service._get_db_access")
    def test_threat_model_not_found_raises_not_found_error(self, mock_get_db_access):
        lock_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table, agent_table)

        agent_table.get_item.return_value = {}

        with pytest.raises(NotFoundError):
            lock_service.acquire_lock("missing", "u1")


class TestRefreshLock:
    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.lock_service._get_db_access")
    def test_successfully_refreshes_lock_with_valid_token(
        self, mock_get_db_access, _mock_time
    ):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u1",
                "lock_token": "valid",
            }
        }

        result = lock_service.refresh_lock("tm-1", "u1", "valid")

        assert result["success"] is True
        lock_table.update_item.assert_called_once()

    @patch("services.lock_service._get_db_access")
    def test_returns_error_if_lock_not_found(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {}

        result = lock_service.refresh_lock("tm-1", "u1", "tok")

        assert result == {"success": False, "message": "Lock not found", "status_code": 410}

    @patch("services.lock_service._get_db_access")
    def test_returns_error_if_lock_held_by_different_user(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u2", "lock_token": "tok"}
        }

        result = lock_service.refresh_lock("tm-1", "u1", "tok")

        assert result["success"] is False
        assert result["held_by"] == "u2"

    @patch("services.lock_service._get_db_access")
    def test_returns_error_if_lock_token_invalid(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u1", "lock_token": "correct"}
        }

        result = lock_service.refresh_lock("tm-1", "u1", "bad")

        assert result["success"] is False
        assert result["message"] == "Invalid lock token"


class TestReleaseLock:
    @patch("services.lock_service._get_db_access")
    def test_successfully_releases_lock_with_valid_token(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u1", "lock_token": "ok"}
        }

        result = lock_service.release_lock("tm-1", "u1", "ok")

        assert result["success"] is True
        lock_table.delete_item.assert_called_once_with(Key={"threat_model_id": "tm-1"})

    @patch("services.lock_service._get_db_access")
    def test_returns_success_if_no_lock_exists(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {}

        result = lock_service.release_lock("tm-1", "u1", "tok")

        assert result["success"] is True
        assert result["message"] == "No lock to release"

    @patch("services.lock_service._get_db_access")
    def test_raises_unauthorized_error_if_user_doesnt_hold_lock(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u2", "lock_token": "tok"}
        }

        with pytest.raises(UnauthorizedError):
            lock_service.release_lock("tm-1", "u1", "tok")

    @patch("services.lock_service._get_db_access")
    def test_raises_unauthorized_error_if_lock_token_invalid(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u1", "lock_token": "correct"}
        }

        with pytest.raises(UnauthorizedError):
            lock_service.release_lock("tm-1", "u1", "wrong")


class TestGetLockStatus:
    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.lock_service.get_username_from_cognito", return_value="testuser")
    @patch("services.lock_service._get_db_access")
    def test_returns_lock_details_when_locked(
        self, mock_get_db_access, _mock_get_username, _mock_time
    ):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u1",
                "lock_token": "tok",
                "lock_timestamp": Decimal("1704067140"),
                "acquired_at": "2024-01-01T00:00:00Z",
                "ttl": Decimal("1704067380"),
            }
        }

        result = lock_service.get_lock_status("tm-1")

        assert result["locked"] is True
        assert result["username"] == "testuser"
        assert isinstance(result["lock_timestamp"], int)
        assert isinstance(result["expires_at"], int)

    @patch("services.lock_service._get_db_access")
    def test_returns_locked_false_when_no_lock(self, mock_get_db_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {}

        result = lock_service.get_lock_status("tm-1")

        assert result == {"locked": False, "message": "No active lock"}

    @patch("services.lock_service.time.time", return_value=1704067200)
    @patch("services.lock_service._get_db_access")
    def test_detects_stale_locks(self, mock_get_db_access, _mock_time):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        lock_table.get_item.return_value = {
            "Item": {
                "threat_model_id": "tm-1",
                "user_id": "u1",
                "lock_token": "tok",
                "lock_timestamp": 1704067200 - lock_service.STALE_LOCK_THRESHOLD - 1,
            }
        }

        result = lock_service.get_lock_status("tm-1")

        assert result["locked"] is False
        assert result["stale"] is True


class TestForceReleaseLock:
    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_owner_can_force_release_lock(self, mock_get_db_access, mock_check_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        mock_check_access.return_value = {
            "is_owner": True,
            "has_access": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {
            "Item": {"threat_model_id": "tm-1", "user_id": "u2"}
        }

        result = lock_service.force_release_lock("tm-1", "owner")

        assert result["success"] is True
        assert result["previous_holder"] == "u2"
        lock_table.delete_item.assert_called_once_with(Key={"threat_model_id": "tm-1"})

    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_non_owner_raises_unauthorized_error(
        self, mock_get_db_access, mock_check_access
    ):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        mock_check_access.return_value = {
            "is_owner": False,
            "has_access": True,
            "access_level": "EDIT",
        }

        with pytest.raises(UnauthorizedError):
            lock_service.force_release_lock("tm-1", "not-owner")

    @patch("services.collaboration_service.check_access")
    @patch("services.lock_service._get_db_access")
    def test_returns_success_if_no_lock_exists(self, mock_get_db_access, mock_check_access):
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(lock_table=lock_table)
        mock_check_access.return_value = {
            "is_owner": True,
            "has_access": True,
            "access_level": "OWNER",
        }
        lock_table.get_item.return_value = {}

        result = lock_service.force_release_lock("tm-1", "owner")

        assert result["success"] is True
        assert result["message"] == "No lock to release"
