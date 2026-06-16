import os
import time
from typing import Any, Dict

import jwt
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext
from jwt import PyJWKClient

logger = Logger()
_JWKS_CLIENTS: Dict[str, PyJWKClient] = {}


def _get_token(event: Dict[str, Any]) -> str:
    auth_header = event.get("authorizationToken", "")
    if not auth_header:
        raise ValueError("Missing Authorization token")

    if auth_header.lower().startswith("bearer "):
        return auth_header[7:]

    return auth_header


def _get_jwks_client(keys_url: str) -> PyJWKClient:
    if keys_url not in _JWKS_CLIENTS:
        _JWKS_CLIENTS[keys_url] = PyJWKClient(keys_url)
    return _JWKS_CLIENTS[keys_url]


def _get_provider_from_token(token: str) -> str:
    configured_provider = os.environ.get("AUTH_PROVIDER", "cognito").strip().lower()
    if configured_provider in {"cognito", "supabase"}:
        return configured_provider

    if configured_provider != "auto":
        raise ValueError(
            "AUTH_PROVIDER must be one of: cognito, supabase, auto"
        )

    claims = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    issuer = str(claims.get("iss", ""))

    if "cognito-idp." in issuer:
        return "cognito"
    if issuer.endswith("/auth/v1") or issuer == "supabase":
        return "supabase"

    if os.environ.get("SUPABASE_URL") or os.environ.get("SUPABASE_JWKS_URL"):
        return "supabase"

    return "cognito"


def _validate_cognito_token(token: str) -> Dict[str, Any]:
    region = os.environ.get("COGNITO_REGION")
    user_pool_id = os.environ.get("COGNITO_USER_POOL_ID")
    app_client_id = os.environ.get("COGNITO_APP_CLIENT_ID")

    if not region or not user_pool_id or not app_client_id:
        raise ValueError(
            "Missing Cognito configuration: COGNITO_REGION, COGNITO_USER_POOL_ID, COGNITO_APP_CLIENT_ID"
        )

    keys_url = (
        f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    )
    signing_key = _get_jwks_client(keys_url).get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=app_client_id,
    )

    return claims


def _validate_supabase_token(token: str) -> Dict[str, Any]:
    supabase_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    jwks_url = os.environ.get("SUPABASE_JWKS_URL", "").strip()
    configured_audience = os.environ.get("SUPABASE_JWT_AUDIENCE", "").strip()
    configured_issuer = os.environ.get("SUPABASE_JWT_ISSUER", "").strip()
    jwt_secret = os.environ.get("SUPABASE_JWT_SECRET", "").strip()

    if not jwks_url and supabase_url:
        jwks_url = f"{supabase_url}/auth/v1/.well-known/jwks.json"

    unverified_header = jwt.get_unverified_header(token)
    algorithm = unverified_header.get("alg", "RS256")
    allowed_algorithms = {"RS256", "ES256", "HS256", "HS384", "HS512"}
    if algorithm not in allowed_algorithms:
        raise ValueError(f"Unsupported Supabase JWT algorithm: {algorithm}")

    decode_kwargs: Dict[str, Any] = {
        "algorithms": [algorithm],
        "options": {
            "verify_aud": bool(configured_audience),
            "verify_iss": False,
        },
    }
    if configured_audience:
        decode_kwargs["audience"] = configured_audience

    if algorithm.startswith("HS"):
        if not jwt_secret:
            raise ValueError(
                "SUPABASE_JWT_SECRET is required for HS* Supabase JWT verification"
            )
        claims = jwt.decode(token, jwt_secret, **decode_kwargs)
    else:
        if not jwks_url:
            raise ValueError(
                "Missing Supabase configuration: SUPABASE_URL or SUPABASE_JWKS_URL"
            )
        signing_key = _get_jwks_client(jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(token, signing_key.key, **decode_kwargs)

    issuer = str(claims.get("iss", ""))
    allowed_issuers = set()
    if configured_issuer:
        allowed_issuers.add(configured_issuer)
    if supabase_url:
        allowed_issuers.add(f"{supabase_url}/auth/v1")
    allowed_issuers.add("supabase")

    if issuer and allowed_issuers and issuer not in allowed_issuers:
        raise ValueError(f"Unexpected Supabase token issuer: {issuer}")

    return claims


def _build_identity_context(claims: Dict[str, Any], auth_provider: str) -> Dict[str, str]:
    user_id = str(claims.get("sub", "")).strip()
    if not user_id:
        raise ValueError("JWT is missing required 'sub' claim")

    email = str(claims.get("email", "") or "").strip()

    if auth_provider == "cognito":
        username = (
            claims.get("cognito:username")
            or claims.get("username")
            or claims.get("preferred_username")
            or claims.get("name")
            or email
            or user_id
        )
    else:
        user_metadata = claims.get("user_metadata")
        if not isinstance(user_metadata, dict):
            user_metadata = {}
        username = (
            claims.get("preferred_username")
            or claims.get("name")
            or claims.get("user_name")
            or user_metadata.get("full_name")
            or user_metadata.get("name")
            or email
            or user_id
        )

    return {
        "user_id": user_id,
        "sub": user_id,
        "username": str(username),
        "email": email,
        "auth_provider": auth_provider,
        "issuer": str(claims.get("iss", "") or ""),
    }


def generate_policy(
    principal_id: str, effect: str, resource: str, context: dict = None
):
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}
            ],
        },
    }
    if context:
        policy["context"] = context
    return policy


@logger.inject_lambda_context
def lambda_handler(event: dict, context: LambdaContext):
    try:
        token = _get_token(event)
        auth_provider = _get_provider_from_token(token)
    except Exception as e:
        logger.error("Failed to prepare token verification", extra={"error": str(e)})
        return generate_policy(
            "unauthorized", "Deny", event.get("methodArn", "*"), {"error": str(e)}
        )

    try:
        if auth_provider == "supabase":
            claims = _validate_supabase_token(token)
        else:
            claims = _validate_cognito_token(token)

        # Check token expiration
        if time.time() > claims["exp"]:
            logger.warning("Token expired", extra={"token_exp": claims["exp"]})
            return generate_policy(
                claims["sub"], "Deny", event["methodArn"], {"error": "Token expired"}
            )

        identity_context = _build_identity_context(claims, auth_provider)
        principal_id = identity_context["user_id"]

        logger.debug(
            "Token validated successfully",
            extra={
                "user_id": identity_context["user_id"],
                "username": identity_context["username"],
                "auth_provider": auth_provider,
            },
        )
        return generate_policy(
            principal_id,
            "Allow",
            event["methodArn"],
            identity_context,
        )

    except Exception as e:
        logger.error(
            "Token validation failed",
            extra={"error": str(e), "auth_provider": auth_provider},
        )
        return generate_policy(
            "unauthorized", "Deny", event["methodArn"], {"error": str(e)}
        )
