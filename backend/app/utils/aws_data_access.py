from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from utils.aws_sdk_compat import ClientError, Config, boto3


class DynamoDBDataAccess:
    """Small facade for DynamoDB table operations with lazy client setup."""

    def __init__(self, region_name: str):
        self._region_name = region_name
        self._resource = None

    def resource(self):
        if self._resource is None:
            self._resource = boto3.resource("dynamodb", region_name=self._region_name)
        return self._resource

    def table(self, table_name: str):
        return self.resource().Table(table_name)

    def get_item(self, table_name: str, key: Dict[str, Any], **kwargs):
        return self.table(table_name).get_item(Key=key, **kwargs)

    def put_item(self, table_name: str, item: Dict[str, Any], **kwargs):
        return self.table(table_name).put_item(Item=item, **kwargs)

    def update_item(self, table_name: str, key: Dict[str, Any], **kwargs):
        return self.table(table_name).update_item(Key=key, **kwargs)

    def delete_item(self, table_name: str, key: Dict[str, Any], **kwargs):
        return self.table(table_name).delete_item(Key=key, **kwargs)

    def query(self, table_name: str, **kwargs):
        return self.table(table_name).query(**kwargs)

    def query_all(self, table_name: str, **kwargs):
        all_items = []
        query_params = dict(kwargs)

        while True:
            response = self.query(table_name, **query_params)
            all_items.extend(response.get("Items", []))
            last_key = response.get("LastEvaluatedKey")
            if not last_key:
                break
            query_params["ExclusiveStartKey"] = last_key

        return all_items

    def batch_get_items(self, request_items: Dict[str, Dict[str, Any]]):
        return self.resource().meta.client.batch_get_item(RequestItems=request_items)

    @contextmanager
    def batch_writer(self, table_name: str) -> Iterator[Any]:
        with self.table(table_name).batch_writer() as batch:
            yield batch


class S3DataAccess:
    """Small facade for S3 operations with dedicated presign client config."""

    def __init__(self, region_name: str):
        self._region_name = region_name
        self._client = None
        self._presign_client = None

    def client(self):
        if self._client is None:
            self._client = boto3.client("s3", region_name=self._region_name)
        return self._client

    def presign_client(self):
        if self._presign_client is None:
            self._presign_client = boto3.client(
                "s3",
                region_name=self._region_name,
                endpoint_url=f"https://s3.{self._region_name}.amazonaws.com",
                config=Config(
                    signature_version="s3v4", s3={"addressing_style": "virtual"}
                ),
            )
        return self._presign_client

    def delete_object(self, bucket_name: str, object_key: str):
        return self.client().delete_object(Bucket=bucket_name, Key=object_key)

    def get_object(self, bucket_name: str, object_key: str) -> bytes:
        """Download object body from S3."""
        resp = self.client().get_object(Bucket=bucket_name, Key=object_key)
        return resp["Body"].read()

    def object_exists(self, bucket_name: str, object_key: str) -> bool:
        """Return True if the object is present (cheap head request)."""
        try:
            self.client().head_object(Bucket=bucket_name, Key=object_key)
            return True
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def generate_presigned_url(
        self,
        client_method: str,
        params: Dict[str, Any],
        expires_in: int,
        http_method: str,
    ) -> str:
        return self.presign_client().generate_presigned_url(
            client_method,
            Params=params,
            ExpiresIn=expires_in,
            HttpMethod=http_method,
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
