"""Deserialize attribute values to native Python types.

In AWS mode, handles DynamoDB stream marshalled format (e.g. {"S": "abc"}).
In local/Supabase mode, data is already native Python types — returned as-is.
"""

import logging

LOG = logging.getLogger(__name__)


def deserialize_dynamodb_image(image: dict) -> dict:
    """Deserialize a stream image to native Python types.

    In AWS mode, the image is in DynamoDB marshalled format:
        {"job_id": {"S": "abc"}, "count": {"N": "5"}}
    Returns native Python dict:
        {"job_id": "abc", "count": Decimal("5")}

    In local/Supabase mode, data is already native types and is returned
    unchanged.

    Args:
        image: Marshalled attribute map or native dict.

    Returns:
        Native Python dict.
    """
    if not image:
        return {}

    first_value = next(iter(image.values()), None)
    if first_value is None:
        return {}

    # Check if this is already a native value (not a type-tagged dict)
    if not isinstance(first_value, dict):
        return image

    type_keys = {"S", "N", "B", "BOOL", "NULL", "L", "M", "SS", "NS", "BS"}
    if not type_keys.intersection(first_value.keys()):
        # Already native types (Supabase/local mode)
        return image

    # DynamoDB marshalled format — deserialize
    from boto3.dynamodb.types import TypeDeserializer

    _deserializer = TypeDeserializer()
    return {key: _deserializer.deserialize(value) for key, value in image.items()}
