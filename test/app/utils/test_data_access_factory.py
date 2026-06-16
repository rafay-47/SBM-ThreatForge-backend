"""Unit tests for Supabase adapter behaviors in data_access_factory."""

import importlib
import sys
from pathlib import Path

import pytest

# Add backend/app to path for imports
backend_path = str(Path(__file__).parent.parent.parent.parent / "backend" / "app")
sys.path.insert(0, backend_path)

try:
    from boto3.dynamodb.conditions import Attr
except ModuleNotFoundError:
    class _ConditionAttribute:
        def __init__(self, name):
            self.name = name

    class Equals:
        def __init__(self, lhs, rhs):
            self._values = (lhs, rhs)

    class Attr:
        def __init__(self, name):
            self._name = name

        def eq(self, value):
            return Equals(_ConditionAttribute(self._name), value)

data_access_factory = importlib.import_module("utils.data_access_factory")
SupabaseTable = data_access_factory.SupabaseTable
SupabaseDataAccess = data_access_factory.SupabaseDataAccess
get_database_access = data_access_factory.get_database_access


class FakeSupabaseClient:
    """Small in-memory fake implementing the HTTP client methods used by SupabaseTable."""

    def __init__(self):
        self.rows = [
            {"id": "a", "owner": "alice", "status": "OPEN", "version": 1},
            {"id": "b", "owner": "alice", "status": "OPEN", "version": 2},
            {"id": "c", "owner": "alice", "status": "OPEN", "version": 3},
            {"id": "d", "owner": "alice", "status": "OPEN", "version": 4},
            {"id": "e", "owner": "alice", "status": "OPEN", "version": 5},
        ]

    def _matches(self, row, filters):
        for column, value in filters:
            if row.get(column) != value:
                return False
        return True

    def select(
        self,
        table_name,
        filters,
        select="*",
        limit=None,
        order=None,
        offset=None,
    ):
        del table_name, select, order
        filtered = [row.copy() for row in self.rows if self._matches(row, filters)]
        start = max(0, int(offset or 0))
        if limit is None:
            return filtered[start:]
        return filtered[start : start + int(limit)]

    def insert(self, table_name, item):
        del table_name
        self.rows.append(item.copy())
        return [item.copy()]

    def update(self, table_name, filters, values):
        del table_name
        updated = []
        for row in self.rows:
            if self._matches(row, filters):
                row.update(values)
                updated.append(row.copy())
        return updated

    def delete(self, table_name, filters):
        del table_name
        self.rows = [row for row in self.rows if not self._matches(row, filters)]


class TestSupabaseTablePagination:
    def test_query_uses_exclusive_start_key_offset_and_returns_continuation(self):
        table = SupabaseTable(FakeSupabaseClient(), "fake")

        response = table.query(
            KeyConditionExpression="owner = :owner",
            ExpressionAttributeValues={":owner": "alice"},
            Limit=2,
            ExclusiveStartKey={"__offset": 1},
        )

        assert [item["id"] for item in response["Items"]] == ["b", "c"]
        assert response["LastEvaluatedKey"] == {"__offset": 3}

    def test_scan_accepts_boto3_condition_objects(self):
        table = SupabaseTable(FakeSupabaseClient(), "fake")

        response = table.scan(FilterExpression=Attr("owner").eq("alice"), Limit=3)

        assert len(response["Items"]) == 3
        assert response["LastEvaluatedKey"] == {"__offset": 3}


class TestSupabaseTableConditions:
    def test_update_item_honors_attribute_not_exists_or_equals_pattern(self):
        table = SupabaseTable(FakeSupabaseClient(), "fake")

        response = table.update_item(
            Key={"id": "a"},
            UpdateExpression="SET #status = :new_status",
            ExpressionAttributeNames={"#status": "status", "#owner": "owner"},
            ExpressionAttributeValues={":new_status": "CLOSED", ":owner": "alice"},
            ConditionExpression="attribute_not_exists(#owner) OR #owner = :owner",
            ReturnValues="ALL_NEW",
        )

        assert response["Attributes"]["status"] == "CLOSED"

    def test_delete_item_honors_simple_owner_condition(self):
        client = FakeSupabaseClient()
        table = SupabaseTable(client, "fake")

        table.delete_item(
            Key={"id": "b"},
            ConditionExpression="#owner = :owner",
            ExpressionAttributeNames={"#owner": "owner"},
            ExpressionAttributeValues={":owner": "alice"},
        )

        remaining_ids = {row["id"] for row in client.rows}
        assert "b" not in remaining_ids

    def test_update_item_raises_conditional_check_failed_on_owner_mismatch(self):
        client = FakeSupabaseClient()
        table = SupabaseTable(client, "fake")

        with pytest.raises(Exception) as exc_info:
            table.update_item(
                Key={"id": "a"},
                UpdateExpression="SET #status = :new_status",
                ExpressionAttributeNames={"#status": "status", "#owner": "owner"},
                ExpressionAttributeValues={":new_status": "CLOSED", ":owner": "bob"},
                ConditionExpression="#owner = :owner",
                ReturnValues="ALL_NEW",
            )

        err = exc_info.value
        assert getattr(err, "response", {}).get("Error", {}).get("Code") == (
            "ConditionalCheckFailedException"
        )
        assert next(row for row in client.rows if row["id"] == "a")["status"] == "OPEN"

    def test_delete_item_raises_conditional_check_failed_on_owner_mismatch(self):
        client = FakeSupabaseClient()
        table = SupabaseTable(client, "fake")

        with pytest.raises(Exception) as exc_info:
            table.delete_item(
                Key={"id": "b"},
                ConditionExpression="#owner = :owner",
                ExpressionAttributeNames={"#owner": "owner"},
                ExpressionAttributeValues={":owner": "bob"},
            )

        err = exc_info.value
        assert getattr(err, "response", {}).get("Error", {}).get("Code") == (
            "ConditionalCheckFailedException"
        )
        remaining_ids = {row["id"] for row in client.rows}
        assert "b" in remaining_ids


class TestDatabaseAccessFactory:
    def test_returns_supabase_access_when_provider_is_supabase(self, monkeypatch):
        monkeypatch.setattr(data_access_factory, "DATABASE_PROVIDER", "supabase")
        monkeypatch.setattr(data_access_factory, "SUPABASE_URL", "https://example.supabase.co")
        monkeypatch.setattr(data_access_factory, "SUPABASE_SERVICE_ROLE_KEY", "service-role-key")

        access = get_database_access()

        assert isinstance(access, SupabaseDataAccess)

    def test_raises_when_supabase_provider_missing_required_config(self, monkeypatch):
        monkeypatch.setattr(data_access_factory, "DATABASE_PROVIDER", "supabase")
        monkeypatch.setattr(data_access_factory, "SUPABASE_URL", "")
        monkeypatch.setattr(data_access_factory, "SUPABASE_SERVICE_ROLE_KEY", "")

        with pytest.raises(ValueError) as exc_info:
            get_database_access()

        assert "SUPABASE_URL" in str(exc_info.value)

    def test_raises_on_unsupported_database_provider(self, monkeypatch):
        monkeypatch.setattr(data_access_factory, "DATABASE_PROVIDER", "unknown-provider")

        with pytest.raises(ValueError) as exc_info:
            get_database_access()

        assert "Unsupported DATABASE_PROVIDER" in str(exc_info.value)
