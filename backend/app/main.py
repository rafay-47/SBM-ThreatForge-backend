"""Local HTTP server entry point for the Threat Designer API.

Wraps the existing APIGatewayRestResolver-compatible router in a FastAPI/ASGI
application served by uvicorn.  Used when DEPLOYMENT_MODE=local.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

# Add parent directory to path so we can import app modules
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response as FastAPIResponse

from utils.powertools_compat import APIGatewayRestResolver, CORSConfig, Response, content_types
from exceptions.exceptions import BadRequestError, InternalError, ViewError
from routes import threat_designer_route, attack_tree_route, space_route
from utils.utils import custom_serializer, mask_sensitive_attributes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("threat-designer-api")

PORTAL_REDIRECT_URL = os.getenv("PORTAL_REDIRECT_URL")
TRUSTED_ORIGINS = os.getenv("TRUSTED_ORIGINS")
AUTH_PROVIDER = os.getenv("AUTH_PROVIDER", "supabase").lower()

default_origin = PORTAL_REDIRECT_URL or "http://localhost:5173"
trusted_origins = [
    origin.strip()
    for origin in (TRUSTED_ORIGINS or default_origin).split(",")
    if origin.strip()
]

cors_config = CORSConfig(
    max_age=100,
    allow_credentials=True,
    allow_origin=default_origin,
    allow_headers=["Content-Type", "Authorization"],
)

# AWS Lambda Powertools-style resolver (existing routing logic)
_resolver = APIGatewayRestResolver(serializer=custom_serializer, cors=cors_config)
_resolver.include_router(threat_designer_route.router)
_resolver.include_router(attack_tree_route.router)
_resolver.include_router(space_route.router)

# ---------------------------------------------------------------------------
# JWT validation helpers (ported from the old http.server-based main.py)
# ---------------------------------------------------------------------------

_JWKS_CACHE: Dict[str, Any] = {}


def _get_jwks(url: str) -> Dict[str, Any]:
    """Fetch and cache JWKS."""
    if url not in _JWKS_CACHE:
        from urllib import request
        req = request.Request(url)
        with request.urlopen(req, timeout=10) as resp:
            _JWKS_CACHE[url] = json.loads(resp.read().decode())
    return _JWKS_CACHE[url]


def _find_signing_key(header: Dict[str, str], jwks: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Find the matching signing key from JWKS."""
    kid = header.get("kid")
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    keys = jwks.get("keys", [])
    return keys[0] if keys else None


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data."""
    import base64
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _validate_token(token: str) -> Dict[str, Any]:
    """Validate JWT token and return claims."""
    import time
    import hashlib
    import hmac

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header = json.loads(_base64url_decode(parts[0]))
    payload = json.loads(_base64url_decode(parts[1]))
    signature = _base64url_decode(parts[2])

    alg = header.get("alg", "HS256")
    logger.debug(f"Token algorithm: {alg}")

    if alg.startswith("HS"):
        secret = os.getenv("SUPABASE_JWT_SECRET", "").strip()
        if secret:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            if alg == "HS256":
                expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            elif alg == "HS384":
                expected = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
            else:
                expected = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("Invalid token signature")
        else:
            logger.warning("SUPABASE_JWT_SECRET not set; skipping JWT signature verification")
            iss = payload.get("iss", "")
            supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
            if supabase_url and not iss.startswith(supabase_url):
                raise ValueError(f"Unexpected token issuer: {iss}")
    else:
        # RSA/EC: verify with JWKS
        supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
        jwks_url = os.getenv("SUPABASE_JWKS_URL", f"{supabase_url}/auth/v1/.well-known/jwks.json")
        if not supabase_url and not os.getenv("SUPABASE_JWKS_URL"):
            raise ValueError("SUPABASE_URL or SUPABASE_JWKS_URL required for RS*/ES* verification")

        try:
            jwks = _get_jwks(jwks_url)
            signing_key = _find_signing_key(header, jwks)
            if not signing_key:
                raise ValueError("No matching signing key found")

            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes

            jwk = signing_key
            kty = jwk.get("kty")
            signing_input = f"{parts[0]}.{parts[1]}".encode()

            if kty == "RSA":
                from cryptography.hazmat.primitives.asymmetric import padding
                n = int.from_bytes(_base64url_decode(jwk["n"]), "big")
                e = int.from_bytes(_base64url_decode(jwk["e"]), "big")
                public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384()}.get(alg, hashes.SHA512())
                public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
            elif kty == "EC":
                from cryptography.hazmat.primitives.asymmetric import ec as asym_ec
                curve_name = jwk.get("crv", "P-256")
                x = int.from_bytes(_base64url_decode(jwk["x"]), "big")
                y = int.from_bytes(_base64url_decode(jwk["y"]), "big")
                curve_map = {"P-256": asym_ec.SECP256R1(), "P-384": asym_ec.SECP384R1(), "P-521": asym_ec.SECP521R1()}
                hash_map = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
                curve = curve_map.get(curve_name, asym_ec.SECP256R1())
                hash_alg = hash_map.get(alg, hashes.SHA256())
                public_key = asym_ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
                public_key.verify(signature, signing_input, asym_ec.ECDSA(hash_alg))
            else:
                raise ValueError(f"Unsupported key type: {kty}")
        except Exception as e:
            logger.warning("JWKS verification failed (%s); falling back to issuer/expiry check", e)
            iss = payload.get("iss", "")
            if supabase_url and not iss.startswith(supabase_url):
                raise ValueError(f"Unexpected token issuer: {iss}")

    # Check expiration
    exp = payload.get("exp")
    if exp and __import__("time").time() > exp:
        raise ValueError("Token expired")

    return payload


def _build_authorizer_context(claims: Dict[str, Any]) -> Dict[str, str]:
    """Build authorizer context from JWT claims."""
    user_id = str(claims.get("sub", "")).strip()
    email = str(claims.get("email", "") or "").strip()

    if AUTH_PROVIDER == "cognito":
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
        "auth_provider": AUTH_PROVIDER,
        "issuer": str(claims.get("iss", "") or ""),
    }


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="Threat Designer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


async def _dispatch(request: Request) -> FastAPIResponse:
    """Translate a FastAPI Request into an API Gateway event, run it through
    the existing resolver, and return a FastAPIResponse."""
    method = request.method.upper()
    path = request.url.path
    query_params = dict(request.query_params)

    body_bytes = await request.body()
    body = body_bytes.decode("utf-8") if body_bytes else None

    headers = dict(request.headers)

    # Build API-Gateway-compatible event
    event = {
        "httpMethod": method,
        "path": path,
        "queryStringParameters": query_params,
        "headers": headers,
        "body": body,
        "requestContext": {
            "authorizer": {},
            "http": {"method": method},
        },
    }

    # JWT validation
    auth_header = headers.get("authorization", headers.get("Authorization", ""))
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            claims = _validate_token(token)
            event["requestContext"]["authorizer"] = _build_authorizer_context(claims)
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
    elif method != "OPTIONS":
        return JSONResponse({"error": "Missing Authorization header"}, status_code=401)

    # Resolve through the existing router
    try:
        result = _resolver.resolve(event, None)
        status = result.get("statusCode", 200)
        resp_body = result.get("body", "")
        resp_headers = {k: v for k, v in result.get("headers", {}).items()}

        # Strip content-type from headers dict so we can pass it explicitly
        content_type = resp_headers.pop(
            "Content-Type",
            resp_headers.pop("content-type", "application/json"),
        )

        return FastAPIResponse(
            content=resp_body.encode("utf-8") if isinstance(resp_body, str) else resp_body,
            status_code=status,
            headers=resp_headers,
            media_type=content_type,
        )
    except Exception as exc:
        logger.error("Request failed: %s", exc, exc_info=True)
        return JSONResponse({"code": type(exc).__name__, "message": str(exc)}, status_code=500)


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all(request: Request, full_path: str) -> FastAPIResponse:
    """Single catch-all route that forwards every request to the resolver."""
    return await _dispatch(request)


# ---------------------------------------------------------------------------
# Uvicorn entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")

    logger.info("Starting Threat Designer API on http://%s:%d", host, port)
    logger.info("Auth provider: %s", AUTH_PROVIDER)

    uvicorn.run(
        app,
        host=host,
        port=port,
        timeout_keep_alive=75,
        access_log=True,
    )
