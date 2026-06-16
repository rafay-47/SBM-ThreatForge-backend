"""Compatibility layer for aws-lambda-powertools in local/non-Lambda runs.

This module prefers the real aws-lambda-powertools package when available.
When unavailable, it provides small, import-compatible fallbacks so backend
modules can still load in local development.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

try:
    from aws_lambda_powertools import Logger, Tracer  # type: ignore[import-not-found]
    from aws_lambda_powertools.event_handler import (  # type: ignore
        APIGatewayRestResolver,
        CORSConfig,
        Response,
        content_types,
    )
    from aws_lambda_powertools.event_handler.api_gateway import Router  # type: ignore
    from aws_lambda_powertools.logging import correlation_paths  # type: ignore
    from aws_lambda_powertools.utilities.typing import LambdaContext  # type: ignore
except ModuleNotFoundError:

    class Logger:
        def __init__(self, service: str = "threat-designer", **_: Any) -> None:
            self._logger = logging.getLogger(service)
            if not self._logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    "%(asctime)s %(levelname)s [%(name)s] %(message)s"
                )
                handler.setFormatter(formatter)
                self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

        def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
            self._logger.debug(msg)

        def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
            self._logger.info(msg)

        def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
            self._logger.warning(msg)

        def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
            self._logger.error(msg)

        def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
            self._logger.exception(msg)

        def inject_lambda_context(self, **_: Any) -> Callable:
            def decorator(func: Callable) -> Callable:
                return func

            return decorator

    class Tracer:
        def capture_lambda_handler(self, func: Optional[Callable] = None, **_: Any):
            if func is None:
                return lambda inner: inner
            return func

        def capture_method(self, func: Optional[Callable] = None, **_: Any):
            if func is None:
                return lambda inner: inner
            return func

    class _ContentTypes:
        APPLICATION_JSON = "application/json"

    content_types = _ContentTypes()

    @dataclass
    class Response:
        status_code: int
        content_type: str
        body: str
        headers: Optional[Dict[str, str]] = None

    @dataclass
    class CORSConfig:
        max_age: int = 0
        allow_credentials: bool = False
        allow_origin: str = "*"
        allow_headers: Optional[List[str]] = None

    class correlation_paths:
        API_GATEWAY_REST = ""

    class LambdaContext:
        pass

    class _RequestContext:
        def __init__(self, authorizer: Optional[Dict[str, Any]] = None) -> None:
            self.authorizer = authorizer or {}

    class _CurrentEvent:
        def __init__(self, event: Optional[Dict[str, Any]] = None) -> None:
            event = event or {}
            headers = event.get("headers") or {}
            request_context = event.get("requestContext") or {}
            authorizer = request_context.get("authorizer") or {}

            self.raw_event = event
            self.path = event.get("path") or event.get("rawPath") or "/"
            self.http_method = (
                event.get("httpMethod")
                or (request_context.get("http") or {}).get("method")
                or "GET"
            )
            self.query_string_parameters = event.get("queryStringParameters") or {}
            self.request_context = _RequestContext(authorizer=authorizer)
            self.headers = headers

            body = event.get("body")
            if isinstance(body, str) and body:
                try:
                    self.json_body = json.loads(body)
                except json.JSONDecodeError:
                    self.json_body = {}
            elif isinstance(body, dict):
                self.json_body = body
            else:
                self.json_body = {}

        def get_header_value(self, name: str, default_value: str = "") -> str:
            if not self.headers:
                return default_value
            return self.headers.get(name) or self.headers.get(name.lower()) or default_value

    class Router:
        def __init__(self) -> None:
            self.current_event = _CurrentEvent()
            self._routes: List[Dict[str, Any]] = []

        def _register(self, method: str, rule: str, func: Callable) -> Callable:
            self._routes.append({"method": method.upper(), "rule": rule, "func": func})
            return func

        def route(self, method: str, rule: str) -> Callable:
            def decorator(func: Callable) -> Callable:
                return self._register(method, rule, func)

            return decorator

        def get(self, rule: str) -> Callable:
            return self.route("GET", rule)

        def post(self, rule: str) -> Callable:
            return self.route("POST", rule)

        def put(self, rule: str) -> Callable:
            return self.route("PUT", rule)

        def delete(self, rule: str) -> Callable:
            return self.route("DELETE", rule)

    class APIGatewayRestResolver:
        def __init__(self, serializer: Optional[Callable] = None, cors: Optional[CORSConfig] = None):
            self._serializer = serializer or json.dumps
            self._cors = cors or CORSConfig()
            self._routes: List[Dict[str, Any]] = []
            self._routers: List[Router] = []
            self._exception_handlers: Dict[type, Callable] = {}
            self.current_event = _CurrentEvent()

        def include_router(self, router: Router) -> None:
            self._routers.append(router)

        def route(self, method: str, rule: str) -> Callable:
            def decorator(func: Callable) -> Callable:
                self._routes.append(
                    {"method": method.upper(), "rule": rule, "func": func}
                )
                return func

            return decorator

        def exception_handler(self, exception_type: type) -> Callable:
            def decorator(func: Callable) -> Callable:
                self._exception_handlers[exception_type] = func
                return func

            return decorator

        def _match_route(self, route_rule: str, path: str) -> Optional[Dict[str, str]]:
            if route_rule == ".*":
                return {}

            pattern = re.sub(r"<([^>]+)>", r"(?P<\1>[^/]+)", route_rule)
            pattern = f"^{pattern}$"
            match = re.match(pattern, path)
            if not match:
                return None
            return match.groupdict()

        def _route_priority(self, route_rule: str) -> tuple[int, int, int]:
            """Prioritize literal routes before parameterized routes.

            This mirrors common router behavior where concrete paths like
            /threat-designer/owned win over /threat-designer/<id>.
            """
            if route_rule == ".*":
                return (10_000, 0, 0)

            dynamic_segments = len(re.findall(r"<[^>]+>", route_rule))
            segment_count = len([seg for seg in route_rule.split("/") if seg])

            # Fewer dynamic segments first, then more specific (longer) paths.
            return (dynamic_segments, -segment_count, -len(route_rule))

        def _serialize(self, result: Any, status_code: int = 200) -> Dict[str, Any]:
            if isinstance(result, Response):
                headers = result.headers or {}
                return {
                    "statusCode": result.status_code,
                    "headers": {
                        "Content-Type": result.content_type,
                        **headers,
                    },
                    "multiValueHeaders": {},
                    "body": result.body,
                }

            body = result
            if isinstance(result, (dict, list)):
                body = self._serializer(result)
            elif result is None:
                body = ""
            else:
                body = str(result)

            return {
                "statusCode": status_code,
                "headers": {"Content-Type": content_types.APPLICATION_JSON},
                "multiValueHeaders": {},
                "body": body,
            }

        def _resolve_exception(self, ex: Exception) -> Dict[str, Any]:
            for exception_type, handler in self._exception_handlers.items():
                if isinstance(ex, exception_type):
                    return self._serialize(handler(ex))
            raise ex

        def resolve(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
            del context
            self.current_event = _CurrentEvent(event)
            method = self.current_event.http_method.upper()
            path = self.current_event.path

            all_routes = list(self._routes)
            for router in self._routers:
                router.current_event = self.current_event
                all_routes.extend(router._routes)

            all_routes = sorted(all_routes, key=lambda route: self._route_priority(route["rule"]))

            for route in all_routes:
                if route["method"] != method:
                    continue

                params = self._match_route(route["rule"], path)
                if params is None:
                    continue

                try:
                    return self._serialize(route["func"](**params))
                except Exception as ex:
                    return self._resolve_exception(ex)

            return self._serialize({"message": "Not Found"}, status_code=404)
