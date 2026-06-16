"""Unit tests for collaboration_service.py."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add backend/app to path for imports
backend_path = str(Path(__file__).parent.parent.parent.parent / "backend" / "app")
sys.path.insert(0, backend_path)

import services.collaboration_service as collaboration_service
from exceptions.exceptions import InternalError, UnauthorizedError


def _build_db_access(agent_table=None, sharing_table=None, lock_table=None):
    agent_table = agent_table or Mock()
    sharing_table = sharing_table or Mock()
    lock_table = lock_table or Mock()

    db_access = Mock()

    def _table(name):
        if name == collaboration_service.AGENT_TABLE:
            return agent_table
        if name == collaboration_service.SHARING_TABLE:
            return sharing_table
        if name == collaboration_service.LOCKS_TABLE:
            return lock_table
        return sharing_table

    db_access.table.side_effect = _table
    return db_access


class TestCheckAccess:
    @patch("services.collaboration_service._get_db_access")
    def test_owner_returns_owner_access(self, mock_get_db_access):
        agent_table = Mock()
        sharing_table = Mock()
        agent_table.get_item.return_value = {"Item": {"owner": "owner-1"}}
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)

        result = collaboration_service.check_access("tm-1", "owner-1")

        assert result == {"has_access": True, "is_owner": True, "access_level": "OWNER"}

    @patch("services.collaboration_service._get_db_access")
    def test_collaborator_returns_shared_access_level(self, mock_get_db_access):
        agent_table = Mock()
        sharing_table = Mock()
        agent_table.get_item.return_value = {"Item": {"owner": "owner-1"}}
        sharing_table.get_item.return_value = {"Item": {"access_level": "EDIT"}}
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)

        result = collaboration_service.check_access("tm-1", "user-2")

        assert result == {"has_access": True, "is_owner": False, "access_level": "EDIT"}

    @patch("services.collaboration_service._get_db_access")
    def test_no_share_record_returns_no_access(self, mock_get_db_access):
        agent_table = Mock()
        sharing_table = Mock()
        agent_table.get_item.return_value = {"Item": {"owner": "owner-1"}}
        sharing_table.get_item.return_value = {}
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)

        result = collaboration_service.check_access("tm-1", "user-2")

        assert result == {"has_access": False, "is_owner": False, "access_level": None}

    @patch("services.collaboration_service._get_db_access")
    def test_missing_threat_model_raises_internal_error(self, mock_get_db_access):
        agent_table = Mock()
        sharing_table = Mock()
        agent_table.get_item.return_value = {}
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)

        with pytest.raises(InternalError) as exc_info:
            collaboration_service.check_access("missing", "owner-1")

        assert "not found" in str(exc_info.value).lower()


class TestShareThreatModel:
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_owner_can_share_and_updates_shared_flag(
        self, mock_check_access, mock_get_db_access
    ):
        sharing_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }

        result = collaboration_service.share_threat_model(
            "tm-1",
            "owner-1",
            [
                {"user_id": "user-2", "access_level": "EDIT"},
                {"user_id": "user-3", "access_level": "READ_ONLY"},
            ],
        )

        assert result["success"] is True
        assert result["shared_count"] == 2
        assert sharing_table.put_item.call_count == 2
        agent_table.update_item.assert_called_once()

    @patch("services.collaboration_service.check_access")
    def test_non_owner_cannot_share(self, mock_check_access):
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": False,
            "access_level": "EDIT",
        }

        with pytest.raises(UnauthorizedError):
            collaboration_service.share_threat_model(
                "tm-1", "user-2", [{"user_id": "user-3", "access_level": "EDIT"}]
            )

    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_invalid_access_level_defaults_to_read_only(
        self, mock_check_access, mock_get_db_access
    ):
        sharing_table = Mock()
        agent_table = Mock()
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }

        collaboration_service.share_threat_model(
            "tm-1",
            "owner-1",
            [{"user_id": "user-2", "access_level": "INVALID"}],
        )

        put_call = sharing_table.put_item.call_args
        assert put_call.kwargs["Item"]["access_level"] == "READ_ONLY"


class TestGetCollaborators:
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.get_user_profile")
    @patch("services.collaboration_service.check_access")
    def test_returns_collaborators_with_directory_details(
        self, mock_check_access, mock_get_user_profile, mock_get_db_access
    ):
        sharing_table = Mock()
        agent_table = Mock()
        sharing_table.query.return_value = {
            "Items": [
                {
                    "threat_model_id": "tm-1",
                    "user_id": "owner-1",
                    "access_level": "EDIT",
                    "shared_at": "2024-01-01T00:00:00Z",
                    "shared_by": "owner-1",
                },
                {
                    "threat_model_id": "tm-1",
                    "user_id": "user-2",
                    "access_level": "EDIT",
                    "shared_at": "2024-01-01T00:00:00Z",
                    "shared_by": "owner-1",
                },
            ]
        }
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_user_profile.side_effect = [
            {"username": "owner", "email": "owner@example.com", "name": "Owner"},
            {"username": "collab", "email": "collab@example.com", "name": "Collab"},
        ]

        result = collaboration_service.get_collaborators("tm-1", "owner-1")

        assert len(result["collaborators"]) == 1
        assert result["collaborators"][0]["user_id"] == "user-2"
        assert result["collaborators"][0]["username"] == "collab"

    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.get_user_profile")
    @patch("services.collaboration_service.check_access")
    def test_directory_lookup_failures_fall_back_to_user_id(
        self, mock_check_access, mock_get_user_profile, mock_get_db_access
    ):
        sharing_table = Mock()
        agent_table = Mock()
        sharing_table.query.return_value = {
            "Items": [
                {
                    "threat_model_id": "tm-1",
                    "user_id": "user-2",
                    "access_level": "EDIT",
                    "shared_at": "2024-01-01T00:00:00Z",
                    "shared_by": "owner-1",
                }
            ]
        }
        mock_get_db_access.return_value = _build_db_access(agent_table, sharing_table)
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_user_profile.side_effect = Exception("lookup failed")

        result = collaboration_service.get_collaborators("tm-1", "owner-1")

        assert result["collaborators"][0]["username"] == "user-2"
        assert result["collaborators"][0]["email"] is None

    @patch("services.collaboration_service.check_access")
    def test_unauthorized_user_cannot_list_collaborators(self, mock_check_access):
        mock_check_access.return_value = {
            "has_access": False,
            "is_owner": False,
            "access_level": None,
        }

        with pytest.raises(UnauthorizedError):
            collaboration_service.get_collaborators("tm-1", "user-2")


class TestRemoveCollaborator:
    @patch("services.lock_service.get_lock_status")
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_owner_can_remove_collaborator(
        self, mock_check_access, mock_get_db_access, mock_get_lock_status
    ):
        sharing_table = Mock()
        agent_table = Mock()
        lock_table = Mock()
        sharing_table.query.return_value = {"Count": 1}
        mock_get_db_access.return_value = _build_db_access(
            agent_table=agent_table, sharing_table=sharing_table, lock_table=lock_table
        )
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_lock_status.return_value = {"locked": False}

        result = collaboration_service.remove_collaborator("tm-1", "owner-1", "user-2")

        assert result["success"] is True
        sharing_table.delete_item.assert_called_once_with(
            Key={"threat_model_id": "tm-1", "user_id": "user-2"}
        )
        agent_table.update_item.assert_not_called()

    @patch("services.lock_service.get_lock_status")
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_releases_lock_when_removed_user_holds_it(
        self, mock_check_access, mock_get_db_access, mock_get_lock_status
    ):
        sharing_table = Mock()
        agent_table = Mock()
        lock_table = Mock()
        sharing_table.query.return_value = {"Count": 1}
        mock_get_db_access.return_value = _build_db_access(
            agent_table=agent_table, sharing_table=sharing_table, lock_table=lock_table
        )
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_lock_status.return_value = {"locked": True, "user_id": "user-2"}

        collaboration_service.remove_collaborator("tm-1", "owner-1", "user-2")

        lock_table.delete_item.assert_called_once_with(Key={"threat_model_id": "tm-1"})

    @patch("services.lock_service.get_lock_status")
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_updates_is_shared_false_when_last_collaborator_removed(
        self, mock_check_access, mock_get_db_access, mock_get_lock_status
    ):
        sharing_table = Mock()
        agent_table = Mock()
        lock_table = Mock()
        sharing_table.query.return_value = {"Count": 0}
        mock_get_db_access.return_value = _build_db_access(
            agent_table=agent_table, sharing_table=sharing_table, lock_table=lock_table
        )
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_lock_status.return_value = {"locked": False}

        collaboration_service.remove_collaborator("tm-1", "owner-1", "user-2")

        agent_table.update_item.assert_called_once()
        call_args = agent_table.update_item.call_args
        assert call_args.kwargs["UpdateExpression"] == "SET is_shared = :false"

    @patch("services.collaboration_service.check_access")
    def test_non_owner_cannot_remove_collaborator(self, mock_check_access):
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": False,
            "access_level": "EDIT",
        }

        with pytest.raises(UnauthorizedError):
            collaboration_service.remove_collaborator("tm-1", "user-2", "user-3")


class TestUpdateCollaboratorAccess:
    @patch("services.lock_service.get_lock_status")
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_owner_can_update_access(
        self, mock_check_access, mock_get_db_access, mock_get_lock_status
    ):
        sharing_table = Mock()
        mock_get_db_access.return_value = _build_db_access(sharing_table=sharing_table)
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_lock_status.return_value = {"locked": False}

        result = collaboration_service.update_collaborator_access(
            "tm-1", "owner-1", "user-2", "EDIT"
        )

        assert result["success"] is True
        sharing_table.update_item.assert_called_once()

    @patch("services.lock_service.get_lock_status")
    @patch("services.collaboration_service._get_db_access")
    @patch("services.collaboration_service.check_access")
    def test_downgrade_to_read_only_releases_lock(
        self, mock_check_access, mock_get_db_access, mock_get_lock_status
    ):
        sharing_table = Mock()
        lock_table = Mock()
        mock_get_db_access.return_value = _build_db_access(
            sharing_table=sharing_table, lock_table=lock_table
        )
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }
        mock_get_lock_status.return_value = {"locked": True, "user_id": "user-2"}

        collaboration_service.update_collaborator_access(
            "tm-1", "owner-1", "user-2", "READ_ONLY"
        )

        lock_table.delete_item.assert_called_once_with(Key={"threat_model_id": "tm-1"})

    @patch("services.collaboration_service.check_access")
    def test_non_owner_cannot_update_access(self, mock_check_access):
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": False,
            "access_level": "EDIT",
        }

        with pytest.raises(UnauthorizedError):
            collaboration_service.update_collaborator_access(
                "tm-1", "user-2", "user-3", "READ_ONLY"
            )

    @patch("services.collaboration_service.check_access")
    def test_invalid_access_level_raises_internal_error(self, mock_check_access):
        mock_check_access.return_value = {
            "has_access": True,
            "is_owner": True,
            "access_level": "OWNER",
        }

        with pytest.raises(InternalError) as exc_info:
            collaboration_service.update_collaborator_access(
                "tm-1", "owner-1", "user-2", "INVALID"
            )

        assert "invalid access level" in str(exc_info.value).lower()


class TestListCognitoUsers:
    @patch("services.collaboration_service.list_directory_users")
    def test_returns_directory_user_list(self, mock_list_directory_users):
        mock_list_directory_users.return_value = {
            "users": [{"user_id": "u1", "username": "user1"}]
        }

        result = collaboration_service.list_cognito_users("user", 10, "u2")

        assert result == {"users": [{"user_id": "u1", "username": "user1"}]}
        mock_list_directory_users.assert_called_once_with("user", 10, "u2")

    @patch("services.collaboration_service.list_directory_users")
    def test_wraps_directory_errors_as_internal_error(self, mock_list_directory_users):
        mock_list_directory_users.side_effect = Exception("directory unavailable")

        with pytest.raises(InternalError):
            collaboration_service.list_cognito_users()


class TestListUsersForSharing:
    @patch("services.collaboration_service.list_cognito_users")
    def test_delegates_to_list_cognito_users(self, mock_list_cognito_users):
        mock_list_cognito_users.return_value = {"users": []}

        result = collaboration_service.list_users_for_sharing("abc", 5, "u1")

        assert result == {"users": []}
        mock_list_cognito_users.assert_called_once_with("abc", 5, "u1")
