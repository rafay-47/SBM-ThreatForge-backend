import copy
import json
import os
from typing import Any, Dict

from utils.powertools_compat import Logger, Tracer
from utils.powertools_compat import (
    APIGatewayRestResolver,
    CORSConfig,
    Response,
    content_types,
)
from utils.powertools_compat import correlation_paths
from utils.powertools_compat import LambdaContext
from exceptions.exceptions import BadRequestError, InternalError, ViewError
from routes import threat_designer_route, attack_tree_route, space_route
from utils.utils import custom_serializer, mask_sensitive_attributes

PORTAL_REDIRECT_URL = os.getenv(key="PORTAL_REDIRECT_URL")
TRUSTED_ORIGINS = os.getenv(key="TRUSTED_ORIGINS")

default_origin = PORTAL_REDIRECT_URL or "http://localhost:5173"
trusted_origins = [
    origin.strip()
    for origin in (TRUSTED_ORIGINS or default_origin).split(",")
    if origin.strip()
]


logger = Logger(serialize_stacktrace=False)
tracer = Tracer()


# Using default CORS configs
cors_config = CORSConfig(
    max_age=100,
    allow_credentials=True,
    allow_origin=default_origin,
    allow_headers=["Content-Type"],
)

app = APIGatewayRestResolver(serializer=custom_serializer, cors=cors_config)
app.include_router(threat_designer_route.router)
app.include_router(attack_tree_route.router)
app.include_router(space_route.router)


@app.route(method="OPTIONS", rule=".*")
# Matches any pre-flight request coming from API Gateway
def preflight_handler():
    """Handles multi-origin preflight requests"""
    origin = app.current_event.get_header_value(name="Origin", default_value="")
    if origin in trusted_origins:
        app._cors.allow_origin = origin
        app._cors.allow_credentials = True


def add_security_headers(response: Dict[str, Any]):
    headers = response.setdefault("multiValueHeaders", {})
    headers["Strict-Transport-Security"] = ["max-age=63072000;"]
    headers["Content-Security-Policy"] = ["default-src 'self'"]
    headers["X-Content-Type-Options"] = ["nosniff"]
    headers["X-Frame-Options"] = ["DENY"]
    origin = app.current_event.get_header_value(name="Origin", default_value="")
    headers["Access-Control-Allow-Origin"] = [origin]
    if origin in trusted_origins:
        headers["Access-Control-Allow-Origin"] = [origin]
        headers["Access-Control-Allow-Credentials"] = ["true"]
    if app.current_event.http_method == "OPTIONS":
        headers["Access-Control-Allow-Methods"] = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS",
        ]
        headers["Access-Control-Allow-Headers"] = ["Content-Type", "authorization"]
        headers["Access-Control-Allow-Credentials"] = ["true"]
    return response


def log_event(event: dict):
    """Makes a copy of incoming event, removes sensitive headers and logs the event."""
    event_copy = copy.deepcopy(event)
    # Remove attributes which might potentially contain sensitive info
    if "headers" in event_copy:
        event_copy.pop("headers")
    if "multiValueHeaders" in event_copy:
        event_copy.pop("multiValueHeaders")
    if "requestContext" in event_copy:
        event_copy.pop("requestContext")
    if "body" in event_copy and event_copy["body"]:
        body = json.loads(event_copy["body"])
        if body:
            mask_sensitive_attributes(body)
            event_copy["body"] = body


def normalize_authorizer_context(event: Dict[str, Any]) -> None:
    """Normalize authorizer context keys for downstream route handlers.

    Route handlers currently read request_context.authorizer.user_id. This helper keeps
    that contract stable across different JWT providers.
    """
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        return

    authorizer = request_context.get("authorizer")
    if not isinstance(authorizer, dict):
        return

    principal_id = authorizer.get("principalId") or authorizer.get("principal_id")
    user_id = authorizer.get("user_id") or authorizer.get("sub") or principal_id

    if not user_id:
        return

    user_id_str = str(user_id)
    authorizer["user_id"] = user_id_str
    authorizer.setdefault("sub", user_id_str)

    if not authorizer.get("username"):
        fallback_username = (
            authorizer.get("preferred_username")
            or authorizer.get("name")
            or authorizer.get("email")
            or user_id_str
        )
        authorizer["username"] = str(fallback_username)

    email = authorizer.get("email")
    if email is None:
        authorizer["email"] = ""
    else:
        authorizer["email"] = str(email)

    request_context["authorizer"] = authorizer


@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    log_event(event)
    normalize_authorizer_context(event)
    return add_security_headers(app.resolve(event, context))


@app.exception_handler(Exception)
def handle_service_errors(ex: Exception):  # global catch all
    logger.error("Internal Server Error")
    error_dict = {"code": type(ex).__name__, "message": str(ex)}
    return build_error_response(error_dict, 500)


@app.exception_handler(InternalError)
def handle_internal_errors(ex: InternalError):  # receives exception raised
    logger.error("Internal Server Error")
    error_dict = {"code": type(ex).__name__, "message": str(ex)}
    return build_error_response(error_dict, 500)


@app.exception_handler(ViewError)
def handle_view_errors(ex: ViewError):  # receives exception raised
    logger.warning("Application Errors")
    return build_error_response(ex.to_dict(), ex.STATUS)


@app.exception_handler(BadRequestError)
def handle_bad_request_errors(ex: BadRequestError):  # receives exception raised
    logger.warning("Bad Request Error")
    # BadRequestError uses 'message' attribute, not 'msg'
    error_message = getattr(ex, "message", str(ex))
    error_dict = {"code": type(ex).__name__, "message": error_message}
    return build_error_response(error_dict, 400)


def build_error_response(msg: Dict[str, str], status: int):
    return Response(
        status_code=status,
        content_type=content_types.APPLICATION_JSON,
        body=json.dumps(msg),
    )
