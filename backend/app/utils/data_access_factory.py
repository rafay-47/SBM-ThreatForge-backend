"""Provider-aware data access factory for backend app services.

Current runtime behavior remains AWS-first. Supabase adapters are implemented as
an MVP with clear limits (focused on simple equality filters and basic CRUD)
to support incremental migration.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as url_error, parse as url_parse, request as url_request

# Deferred AWS imports — only loaded when DATABASE_PROVIDER=aws or STORAGE_PROVIDER=aws
DynamoDBDataAccess = None
S3DataAccess = None
ClientError = Exception


def _ensure_aws_imports():
    global DynamoDBDataAccess, S3DataAccess, ClientError
    if DynamoDBDataAccess is None:
        from utils.aws_data_access import DynamoDBDataAccess as _DDB
        from utils.aws_sdk_compat import ClientError as _CE
        from utils.aws_data_access import S3DataAccess as _S3
        DynamoDBDataAccess = _DDB
        S3DataAccess = _S3
        ClientError = _CE


from utils.service_contracts import (
    DATABASE_PROVIDER,
    REGION,
    STORAGE_PROVIDER,
    SUPABASE_SERVICE_ROLE_KEY,
    SUPABASE_URL,
)


class SupabaseAdapterError(RuntimeError):
    """Raised when a Supabase adapter operation cannot be completed."""


class SupabaseAdapterNotSupported(NotImplementedError):
    """Raised for DynamoDB semantics not mapped in the current Supabase MVP."""


def _fix_supabase_storage_signed_url(url: str) -> str:
    """Storage REST paths must include /storage/v1; APIs sometimes omit it in signedURL."""
    if not url or "/storage/v1/" in url:
        return url
    # Wrong: https://<ref>.supabase.co/object/sign/...  →  .../storage/v1/object/sign/...
    if "/object/" in url and "supabase.co" in url:
        return url.replace("/object/", "/storage/v1/object/", 1)
    return url


def _postgrest_literal(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _normalize_column(identifier: str, names: Optional[Dict[str, str]]) -> str:
    if identifier.startswith("#"):
        if not names or identifier not in names:
            raise SupabaseAdapterError(
                f"Missing ExpressionAttributeNames mapping for {identifier}"
            )
        return names[identifier]
    return identifier


def _parse_equality_expression(
    expression: str,
    names: Optional[Dict[str, str]],
    values: Optional[Dict[str, Any]],
) -> List[Tuple[str, Any]]:
    if not expression:
        return []

    if "attribute_not_exists" in expression or " OR " in expression:
        raise SupabaseAdapterNotSupported(
            "DynamoDB conditional expressions with attribute_not_exists/OR are not mapped yet."
        )

    if values is None:
        values = {}

    conditions: List[Tuple[str, Any]] = []
    parts = [p.strip() for p in expression.split("AND") if p.strip()]
    pattern = re.compile(r"^([#A-Za-z0-9_]+)\s*=\s*(:[A-Za-z0-9_]+)$")

    for part in parts:
        match = pattern.match(part)
        if not match:
            raise SupabaseAdapterNotSupported(
                f"Unsupported expression fragment for Supabase adapter: {part}"
            )

        raw_col, raw_val = match.groups()
        column = _normalize_column(raw_col, names)
        if raw_val not in values:
            raise SupabaseAdapterError(
                f"Missing ExpressionAttributeValues value for {raw_val}"
            )
        conditions.append((column, values[raw_val]))

    return conditions


def _projection_to_select(
    projection: Optional[str],
    names: Optional[Dict[str, str]],
) -> str:
    if not projection:
        return "*"

    columns = [c.strip() for c in projection.split(",") if c.strip()]
    resolved = [_normalize_column(c, names) for c in columns]
    return ",".join(resolved) if resolved else "*"


def _parse_condition_object_to_pairs(expression: Any) -> List[Tuple[str, Any]]:
    """Parse supported boto3 condition objects into simple equality pairs.

    Currently supported:
    - Equals(Key("col"), value)
    - Equals(Attr("col"), value)
    - And(expr1, expr2, ...)
    """
    expression_type = type(expression).__name__

    if expression_type == "Equals" and hasattr(expression, "_values"):
        values = getattr(expression, "_values", ())
        if len(values) != 2:
            raise SupabaseAdapterNotSupported(
                "Unsupported Equals condition shape for Supabase adapter."
            )

        lhs, rhs = values
        column = getattr(lhs, "name", None)
        if not column:
            raise SupabaseAdapterNotSupported(
                "Unsupported Equals lhs for Supabase adapter (missing column name)."
            )
        return [(str(column), rhs)]

    if expression_type == "And" and hasattr(expression, "_values"):
        pairs: List[Tuple[str, Any]] = []
        for part in getattr(expression, "_values", ()):
            pairs.extend(_parse_condition_object_to_pairs(part))
        return pairs

    raise SupabaseAdapterNotSupported(
        f"Unsupported condition object type for Supabase adapter: {expression_type}"
    )


def _raise_conditional_check_failed(operation_name: str, message: str) -> None:
    raise ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": message,
            }
        },
        operation_name,
    )


def _evaluate_condition_expression(
    current_item: Dict[str, Any],
    expression: str,
    names: Optional[Dict[str, str]],
    values: Optional[Dict[str, Any]],
) -> bool:
    if not expression:
        return True

    if values is None:
        values = {}

    clauses = [c.strip() for c in expression.split("AND") if c.strip()]
    simple_eq_pattern = re.compile(r"^([#A-Za-z0-9_]+)\s*=\s*(:[A-Za-z0-9_]+)$")
    absent_or_eq_pattern = re.compile(
        r"^attribute_not_exists\(([^)]+)\)\s+OR\s+([#A-Za-z0-9_]+)\s*=\s*(:[A-Za-z0-9_]+)$"
    )

    for clause in clauses:
        if " OR " in clause:
            match = absent_or_eq_pattern.match(clause)
            if not match:
                raise SupabaseAdapterNotSupported(
                    f"Unsupported conditional clause for Supabase adapter: {clause}"
                )

            absent_col_raw, eq_col_raw, value_key = match.groups()
            absent_col = _normalize_column(absent_col_raw.strip(), names)
            eq_col = _normalize_column(eq_col_raw, names)

            if value_key not in values:
                raise SupabaseAdapterError(
                    f"Missing ExpressionAttributeValues value for {value_key}"
                )

            expected = values[value_key]
            is_absent = absent_col not in current_item or current_item.get(absent_col) is None
            is_equal = current_item.get(eq_col) == expected
            if not (is_absent or is_equal):
                return False
            continue

        match = simple_eq_pattern.match(clause)
        if not match:
            raise SupabaseAdapterNotSupported(
                f"Unsupported conditional clause for Supabase adapter: {clause}"
            )

        raw_col, value_key = match.groups()
        column = _normalize_column(raw_col, names)
        if value_key not in values:
            raise SupabaseAdapterError(
                f"Missing ExpressionAttributeValues value for {value_key}"
            )

        if current_item.get(column) != values[value_key]:
            return False

    return True


class _SupabaseHttpClient:
    def __init__(self, supabase_url: str, service_role_key: str):
        self._supabase_url = supabase_url.rstrip("/")
        self._service_role_key = service_role_key

    def _headers(self, include_json: bool = True) -> Dict[str, str]:
        headers = {
            "apikey": self._service_role_key,
            "Authorization": f"Bearer {self._service_role_key}",
        }
        if include_json:
            headers["Content-Type"] = "application/json"
        return headers

    def _request(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
        prefer: Optional[str] = None,
        include_json_header: bool = True,
    ) -> Any:
        include_json = include_json_header and (payload is not None)
        headers = self._headers(include_json=include_json)
        if prefer:
            headers["Prefer"] = prefer

        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        req = url_request.Request(url, data=body, method=method, headers=headers)
        try:
            with url_request.urlopen(req, timeout=90) as response:
                raw = response.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except url_error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
            raise SupabaseAdapterError(
                f"Supabase request failed ({method} {url}) [{e.code}]: {detail}"
            )
        except url_error.URLError as e:
            raise SupabaseAdapterError(f"Supabase request failed ({method} {url}): {e}")

    def _rest_url(self, table_name: str, params: Optional[Dict[str, str]] = None) -> str:
        path = f"{self._supabase_url}/rest/v1/{url_parse.quote(table_name, safe='')}"
        if not params:
            return path
        return f"{path}?{url_parse.urlencode(params, doseq=True)}"

    def select(
        self,
        table_name: str,
        filters: List[Tuple[str, Any]],
        select: str = "*",
        limit: Optional[int] = None,
        order: Optional[str] = None,
        offset: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        base_params: Dict[str, str] = {"select": select}
        for column, value in filters:
            base_params[column] = f"eq.{_postgrest_literal(value)}"
        if order:
            base_params["order"] = order

        start_offset = max(0, int(offset or 0))

        # No explicit limit: read all pages to avoid default PostgREST truncation.
        if limit is None:
            page_size = 1000
            all_rows: List[Dict[str, Any]] = []
            current_offset = start_offset

            while True:
                params = dict(base_params)
                params["limit"] = str(page_size)
                params["offset"] = str(current_offset)
                url = self._rest_url(table_name, params)
                data = self._request("GET", url, include_json_header=False)
                rows = data if isinstance(data, list) else []
                all_rows.extend(rows)
                if len(rows) < page_size:
                    break
                current_offset += page_size

            return all_rows

        params = dict(base_params)
        params["limit"] = str(int(limit))
        if start_offset:
            params["offset"] = str(start_offset)

        url = self._rest_url(table_name, params)
        data = self._request("GET", url, include_json_header=False)
        if isinstance(data, list):
            return data
        return []

    def insert(self, table_name: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = self._rest_url(table_name)
        data = self._request(
            "POST",
            url,
            payload=item,
            prefer="return=representation,resolution=merge-duplicates",
        )
        if isinstance(data, list):
            return data
        return []

    def update(
        self,
        table_name: str,
        filters: List[Tuple[str, Any]],
        values: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        params: Dict[str, str] = {}
        for column, value in filters:
            params[column] = f"eq.{_postgrest_literal(value)}"

        url = self._rest_url(table_name, params)
        data = self._request(
            "PATCH",
            url,
            payload=values,
            prefer="return=representation",
        )
        if isinstance(data, list):
            return data
        return []

    def delete(self, table_name: str, filters: List[Tuple[str, Any]]) -> None:
        params: Dict[str, str] = {}
        for column, value in filters:
            params[column] = f"eq.{_postgrest_literal(value)}"
        url = self._rest_url(table_name, params)
        self._request("DELETE", url, prefer="return=minimal")

    def storage_request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self._supabase_url}/storage/v1/{path.lstrip('/')}"
        return self._request(method, url, payload=payload)

    def normalize_signed_url(self, payload: Dict[str, Any]) -> str:
        maybe_url = payload.get("signedURL") or payload.get("signedUrl") or payload.get(
            "url"
        )
        token = payload.get("token")
        if not maybe_url:
            raise SupabaseAdapterError("Supabase storage response missing signed URL")

        url_value = str(maybe_url)
        if token and "token=" not in url_value:
            separator = "&" if "?" in url_value else "?"
            url_value = f"{url_value}{separator}token={token}"

        if url_value.startswith("http://") or url_value.startswith("https://"):
            return _fix_supabase_storage_signed_url(url_value)

        prefix = "" if url_value.startswith("/") else "/"
        joined = f"{self._supabase_url}{prefix}{url_value}"
        return _fix_supabase_storage_signed_url(joined)


class SupabaseTable:
    """Table-like wrapper that mimics core boto3 Table operations."""

    def __init__(self, client: _SupabaseHttpClient, table_name: str):
        self._client = client
        self._table_name = table_name

    def get_item(self, Key: Dict[str, Any], **kwargs):
        select = _projection_to_select(
            kwargs.get("ProjectionExpression"),
            kwargs.get("ExpressionAttributeNames"),
        )
        filters = list(Key.items())
        rows = self._client.select(self._table_name, filters=filters, select=select, limit=1)
        if not rows:
            return {}
        return {"Item": rows[0]}

    def put_item(self, Item: Dict[str, Any], **kwargs):
        del kwargs
        self._client.insert(self._table_name, item=Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def update_item(
        self,
        Key: Dict[str, Any],
        UpdateExpression: str,
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        ReturnValues: Optional[str] = None,
        ConditionExpression: Optional[str] = None,
        **kwargs,
    ):
        del kwargs

        if not UpdateExpression.startswith("SET "):
            raise SupabaseAdapterNotSupported(
                "Only SET UpdateExpression is currently supported for Supabase adapter."
            )

        current_response = self.get_item(Key=Key)
        current_item = current_response.get("Item")

        condition_filters: List[Tuple[str, Any]] = []
        if ConditionExpression:
            if current_item is None:
                _raise_conditional_check_failed(
                    "UpdateItem",
                    "Condition check failed: target item not found",
                )

            if not _evaluate_condition_expression(
                current_item,
                ConditionExpression,
                ExpressionAttributeNames,
                ExpressionAttributeValues,
            ):
                _raise_conditional_check_failed(
                    "UpdateItem",
                    "Condition check failed",
                )

            # Apply atomic server-side equality filters when possible.
            if "attribute_not_exists" not in ConditionExpression and " OR " not in ConditionExpression:
                condition_filters = _parse_equality_expression(
                    ConditionExpression,
                    ExpressionAttributeNames,
                    ExpressionAttributeValues,
                )

        assignments = [
            part.strip() for part in UpdateExpression[len("SET ") :].split(",") if part.strip()
        ]
        value_map = ExpressionAttributeValues or {}
        update_values: Dict[str, Any] = {}

        for assignment in assignments:
            match = re.match(r"^([#A-Za-z0-9_]+)\s*=\s*(:[A-Za-z0-9_]+)$", assignment)
            if not match:
                raise SupabaseAdapterNotSupported(
                    f"Unsupported update assignment for Supabase adapter: {assignment}"
                )

            raw_column, raw_value = match.groups()
            column = _normalize_column(raw_column, ExpressionAttributeNames)
            if raw_value not in value_map:
                raise SupabaseAdapterError(
                    f"Missing ExpressionAttributeValues value for {raw_value}"
                )
            update_values[column] = value_map[raw_value]

        filters = list(Key.items()) + condition_filters
        updated_rows = self._client.update(self._table_name, filters=filters, values=update_values)

        if ConditionExpression and not updated_rows:
            _raise_conditional_check_failed(
                "UpdateItem",
                "Condition check failed",
            )

        if ReturnValues == "ALL_NEW":
            row = updated_rows[0] if updated_rows else None
            if row is None:
                current = self.get_item(Key=Key)
                row = current.get("Item")
            return {"Attributes": row or {}}

        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_item(
        self,
        Key: Dict[str, Any],
        ConditionExpression: Optional[str] = None,
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        del kwargs

        current_response = self.get_item(Key=Key)
        current_item = current_response.get("Item")
        condition_filters: List[Tuple[str, Any]] = []

        if ConditionExpression:
            if current_item is None:
                _raise_conditional_check_failed(
                    "DeleteItem",
                    "Condition check failed: target item not found",
                )

            if not _evaluate_condition_expression(
                current_item,
                ConditionExpression,
                ExpressionAttributeNames,
                ExpressionAttributeValues,
            ):
                _raise_conditional_check_failed(
                    "DeleteItem",
                    "Condition check failed",
                )

            if "attribute_not_exists" not in ConditionExpression and " OR " not in ConditionExpression:
                condition_filters = _parse_equality_expression(
                    ConditionExpression,
                    ExpressionAttributeNames,
                    ExpressionAttributeValues,
                )

        self._client.delete(
            self._table_name,
            filters=list(Key.items()) + condition_filters,
        )

        if ConditionExpression and self.get_item(Key=Key).get("Item") is not None:
            _raise_conditional_check_failed(
                "DeleteItem",
                "Condition check failed",
            )

        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def query(
        self,
        KeyConditionExpression: Any,
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ProjectionExpression: Optional[str] = None,
        Limit: Optional[int] = None,
        ExclusiveStartKey: Optional[Dict[str, Any]] = None,
        ScanIndexForward: bool = True,
        Select: Optional[str] = None,
        **kwargs,
    ):
        del kwargs

        if isinstance(KeyConditionExpression, str):
            filters = _parse_equality_expression(
                KeyConditionExpression,
                ExpressionAttributeNames,
                ExpressionAttributeValues,
            )
        else:
            filters = _parse_condition_object_to_pairs(KeyConditionExpression)

        select = _projection_to_select(ProjectionExpression, ExpressionAttributeNames)

        order = None
        if not ScanIndexForward:
            # Map table name to its correct timestamp sorting column
            if self._table_name in ("sharing", "space_sharing"):
                order = "shared_at.desc"
            elif self._table_name == "space_documents":
                order = "uploaded_at.desc"
            elif self._table_name in ("spaces", "spaces-bucket"):
                order = "created_at.desc"
            else:
                order = "timestamp.desc"

        offset = 0
        if isinstance(ExclusiveStartKey, dict):
            try:
                offset = max(0, int(ExclusiveStartKey.get("__offset", 0)))
            except (TypeError, ValueError):
                offset = 0

        fetch_limit = int(Limit) + 1 if Limit is not None else None

        rows = self._client.select(
            self._table_name,
            filters=filters,
            select=select,
            limit=fetch_limit,
            order=order,
            offset=offset,
        )

        has_more = False
        if Limit is not None and len(rows) > int(Limit):
            has_more = True
            rows = rows[: int(Limit)]

        response: Dict[str, Any] = {"Items": rows, "Count": len(rows)}
        if has_more:
            response["LastEvaluatedKey"] = {"__offset": offset + int(Limit)}

        if Select == "COUNT":
            count_response: Dict[str, Any] = {"Count": len(rows), "Items": []}
            if has_more:
                count_response["LastEvaluatedKey"] = {
                    "__offset": offset + int(Limit)
                }
            return count_response

        return response

    def scan(
        self,
        FilterExpression: Optional[Any] = None,
        ExpressionAttributeValues: Optional[Dict[str, Any]] = None,
        ExpressionAttributeNames: Optional[Dict[str, str]] = None,
        ProjectionExpression: Optional[str] = None,
        Limit: Optional[int] = None,
        ExclusiveStartKey: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        del kwargs

        if FilterExpression is None:
            filters: List[Tuple[str, Any]] = []
        elif isinstance(FilterExpression, str):
            filters = _parse_equality_expression(
                FilterExpression,
                ExpressionAttributeNames,
                ExpressionAttributeValues,
            )
        else:
            filters = _parse_condition_object_to_pairs(FilterExpression)

        select = _projection_to_select(ProjectionExpression, ExpressionAttributeNames)

        offset = 0
        if isinstance(ExclusiveStartKey, dict):
            try:
                offset = max(0, int(ExclusiveStartKey.get("__offset", 0)))
            except (TypeError, ValueError):
                offset = 0

        fetch_limit = int(Limit) + 1 if Limit is not None else None
        rows = self._client.select(
            self._table_name,
            filters=filters,
            select=select,
            limit=fetch_limit,
            offset=offset,
        )

        has_more = False
        if Limit is not None and len(rows) > int(Limit):
            has_more = True
            rows = rows[: int(Limit)]

        response: Dict[str, Any] = {"Items": rows, "Count": len(rows)}
        if has_more:
            response["LastEvaluatedKey"] = {"__offset": offset + int(Limit)}

        return response

    def batch_writer(self):
        return SupabaseBatchWriter(self)


class SupabaseBatchWriter:
    def __init__(self, table: SupabaseTable):
        self._table = table

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        del exc_type, exc, tb
        return False

    def put_item(self, Item: Dict[str, Any]):
        self._table.put_item(Item=Item)

    def delete_item(self, Key: Dict[str, Any]):
        self._table.delete_item(Key=Key)


class SupabaseDataAccess:
    """Supabase database adapter with DynamoDB-like response shape."""

    def __init__(self, supabase_url: str, service_role_key: str):
        self._client = _SupabaseHttpClient(supabase_url, service_role_key)

    def resource(self):
        return self

    def table(self, table_name: str):
        return SupabaseTable(self._client, table_name)

    def get_item(self, table_name: str, key: dict, **kwargs):
        return self.table(table_name).get_item(Key=key, **kwargs)

    def put_item(self, table_name: str, item: dict, **kwargs):
        return self.table(table_name).put_item(Item=item, **kwargs)

    def update_item(self, table_name: str, key: dict, **kwargs):
        return self.table(table_name).update_item(Key=key, **kwargs)

    def delete_item(self, table_name: str, key: dict, **kwargs):
        return self.table(table_name).delete_item(Key=key, **kwargs)

    def query(self, table_name: str, **kwargs):
        return self.table(table_name).query(**kwargs)

    def query_all(self, table_name: str, **kwargs):
        items = []
        response = self.table(table_name).query(**kwargs)
        items.extend(response.get("Items", []))
        return items

    def batch_get_items(self, request_items: dict):
        responses: Dict[str, List[Dict[str, Any]]] = {}
        for table_name, request in request_items.items():
            table = self.table(table_name)
            rows: List[Dict[str, Any]] = []
            for key in request.get("Keys", []):
                item_response = table.get_item(
                    Key=key,
                    ProjectionExpression=request.get("ProjectionExpression"),
                    ExpressionAttributeNames=request.get("ExpressionAttributeNames"),
                )
                if "Item" in item_response:
                    rows.append(item_response["Item"])
            responses[table_name] = rows

        return {"Responses": responses, "UnprocessedKeys": {}}

    def batch_writer(self, table_name: str):
        return SupabaseBatchWriter(self.table(table_name))


class SupabaseStorageAccess:
    """Supabase storage adapter with S3-like helper methods."""

    def __init__(self, supabase_url: str, service_role_key: str):
        self._client = _SupabaseHttpClient(supabase_url, service_role_key)

    def client(self):
        return self

    def presign_client(self):
        return self

    def delete_object(self, bucket_name: str, object_key: str):
        escaped_key = url_parse.quote(object_key, safe="")
        try:
            self._client.storage_request(
                "DELETE",
                f"object/{url_parse.quote(bucket_name, safe='')}/{escaped_key}",
            )
        except SupabaseAdapterError as e:
            if "not found" in str(e).lower() or "404" in str(e):
                pass
            else:
                raise
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def object_exists(self, bucket_name: str, object_key: str) -> bool:
        """Return True if the object exists. Uses HEAD; if HEAD is unsupported, assume True."""
        escaped_bucket = url_parse.quote(bucket_name, safe="")
        escaped_key = url_parse.quote(object_key, safe="")
        url = f"{self._client._supabase_url}/storage/v1/object/{escaped_bucket}/{escaped_key}"
        req = url_request.Request(url, method="HEAD", headers=self._client._headers(include_json=False))
        try:
            with url_request.urlopen(req, timeout=15) as resp:
                return 200 <= resp.status < 300
        except url_error.HTTPError as e:
            if e.code == 404:
                return False
            if e.code in (405, 501):
                return True
            detail = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
            raise SupabaseAdapterError(
                f"Supabase storage HEAD failed [{e.code}]: {detail}"
            )
        except url_error.URLError as e:
            raise SupabaseAdapterError(f"Supabase storage HEAD failed: {e}")

    def generate_presigned_url(
        self,
        client_method: str,
        params: dict,
        expires_in: int,
        http_method: str,
    ) -> str:
        bucket = params.get("Bucket")
        key = params.get("Key")
        if not bucket or not key:
            raise SupabaseAdapterError(
                "Supabase storage adapter requires Params with Bucket and Key."
            )

        if client_method == "get_object" and http_method == "GET":
            payload = self._client.storage_request(
                "POST",
                f"object/sign/{url_parse.quote(bucket, safe='')}/{url_parse.quote(key, safe='')}",
                payload={"expiresIn": int(expires_in)},
            )
            if not isinstance(payload, dict):
                raise SupabaseAdapterError("Unexpected Supabase signed URL response")
            return self._client.normalize_signed_url(payload)

        if client_method == "put_object" and http_method == "PUT":
            payload = self._client.storage_request(
                "POST",
                f"object/upload/sign/{url_parse.quote(bucket, safe='')}/{url_parse.quote(key, safe='')}",
                payload={"expiresIn": int(expires_in)},
            )
            if not isinstance(payload, dict):
                raise SupabaseAdapterError("Unexpected Supabase signed upload URL response")
            return self._client.normalize_signed_url(payload)

        raise SupabaseAdapterNotSupported(
            f"Unsupported storage presign combination: {client_method} {http_method}"
        )

    def generate_presigned_put_object(
        self, bucket_name: str, object_key: str, file_type: str, expiration: int
    ) -> str:
        return self.generate_presigned_url(
            "put_object",
            params={
                "Bucket": bucket_name,
                "Key": object_key,
                "ContentType": file_type,
            },
            expires_in=expiration,
            http_method="PUT",
        )

    def get_object(self, bucket_name: str, object_key: str) -> bytes:
        """Download file content directly from Supabase storage."""
        escaped_bucket = url_parse.quote(bucket_name, safe="")
        escaped_key = url_parse.quote(object_key, safe="")
        url = f"{self._client._supabase_url}/storage/v1/object/{escaped_bucket}/{escaped_key}"
        headers = self._client._headers(include_json=False)
        req = url_request.Request(url, headers=headers)
        try:
            with url_request.urlopen(req, timeout=90) as response:
                return response.read()
        except url_error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
            raise SupabaseAdapterError(
                f"Supabase storage download failed [{e.code}]: {detail}"
            )
        except url_error.URLError as e:
            raise SupabaseAdapterError(f"Supabase storage download failed: {e}")

    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """Upload file content directly to Supabase storage."""
        escaped_bucket = url_parse.quote(bucket_name, safe="")
        escaped_key = url_parse.quote(object_key, safe="")
        url = f"{self._client._supabase_url}/storage/v1/object/{escaped_bucket}/{escaped_key}"
        headers = self._client._headers(include_json=False)
        headers["Content-Type"] = content_type
        req = url_request.Request(url, data=data, method="POST", headers=headers)
        try:
            with url_request.urlopen(req, timeout=90) as response:
                raw = response.read().decode("utf-8")
                result = json.loads(raw) if raw else {}
                return {"ResponseMetadata": {"HTTPStatusCode": response.status, "Key": object_key, "result": result}}
        except url_error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="ignore") if e.fp else str(e)
            raise SupabaseAdapterError(
                f"Supabase storage upload failed [{e.code}]: {detail}"
            )
        except url_error.URLError as e:
            raise SupabaseAdapterError(f"Supabase storage upload failed: {e}")


def _normalize_provider(value: Optional[str], default: str) -> str:
    return (value or default).strip().lower()


def _validate_supabase_config() -> None:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise ValueError(
            "Supabase provider is selected but SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY is missing."
        )


def get_database_access(region_name: Optional[str] = None) -> Any:
    provider = _normalize_provider(DATABASE_PROVIDER, "aws")
    if provider in {"aws", "dynamodb"}:
        _ensure_aws_imports()
        return DynamoDBDataAccess(region_name=region_name or REGION)

    if provider == "supabase":
        _validate_supabase_config()
        return SupabaseDataAccess(
            supabase_url=SUPABASE_URL,
            service_role_key=SUPABASE_SERVICE_ROLE_KEY,
        )

    raise ValueError(f"Unsupported DATABASE_PROVIDER: {provider}")


def get_storage_access(region_name: Optional[str] = None) -> Any:
    provider = _normalize_provider(STORAGE_PROVIDER, "aws")
    if provider in {"aws", "s3"}:
        _ensure_aws_imports()
        return S3DataAccess(region_name=region_name or REGION)

    if provider == "supabase":
        _validate_supabase_config()
        return SupabaseStorageAccess(
            supabase_url=SUPABASE_URL,
            service_role_key=SUPABASE_SERVICE_ROLE_KEY,
        )

    raise ValueError(f"Unsupported STORAGE_PROVIDER: {provider}")
