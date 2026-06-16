import json
from datetime import date, datetime, timezone
from enum import Enum
from json import JSONEncoder

from utils.powertools_compat import Logger, Tracer
from utils.powertools_compat import Router
from utils.data_access_factory import get_database_access
from utils.env_defaults import get_region
from exceptions.exceptions import UnauthorizedError

tracer = Tracer()
logger = Logger()

sensitive_attributes = [
    "email",
    "username",
    "firstName",
    "lastName",
    "businessAddress",
    "address",
]


class CustomEncoder(JSONEncoder):
    """Custom encoder for objects not serializable by default json code"""

    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, type(None)):
            return ""
        try:
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return sorted(iterable)
        return JSONEncoder.default(self, obj)


def custom_serializer(obj) -> str:
    """Custom serializer function ApiGatewayResolver can use"""
    return json.dumps(obj, cls=CustomEncoder)


def mask_sensitive_attributes(payload: dict):
    """Redacts the values in dict based on sensitive key names configured."""
    for k, v in payload.items():
        if isinstance(v, dict):
            mask_sensitive_attributes(v)
        if k in sensitive_attributes:
            payload[k] = "[REDACTED]"


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def validate_user(router: Router):
    """
    Decorator to validate the API call against the owner in request body.
    :param router: Router to get current event
    :return: Throws an error or forwards the call to service
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            body = router.current_event.json_body
            owner = body.get("owner", None)
            user_id = router.current_event.request_context.authorizer.get(
                "username", ""
            )
            email = router.current_event.request_context.authorizer.get("email", "")

            if user_id == owner:
                return func(*args, **kwargs)
            else:
                logger.error("Owner does not match the authenticated user")
                raise UnauthorizedError(
                    f"User: {email} is not authorized to access this resource."
                )

        return wrapper

    return decorator


def create_dynamodb_item(agent_state, table_name):
    """Create item in database (Supabase or DynamoDB via factory)."""
    db = get_database_access(region_name=get_region())
    table = db.table(table_name)

    # Get current UTC timestamp
    current_utc = datetime.now(timezone.utc).isoformat()

    # Convert Pydantic model to dict, handling nested Pydantic objects and existing dicts
    item = {
        "job_id": agent_state["job_id"],
        "s3_location": agent_state["s3_location"],
        "title": agent_state.get("title", None),
        "owner": agent_state.get("owner", None),
        "retry": agent_state.get("retry", None),
        "timestamp": current_utc,
    }

    try:
        response = table.put_item(Item=item)
        logger.debug("Item created successfully:", response)
    except Exception as e:
        error_msg = str(e)
        if hasattr(e, "response") and isinstance(e.response, dict):
            error_msg = e.response.get("Error", {}).get("Message", error_msg)
        logger.error("Error creating item:", error_msg)
        raise
