"""User directory abstraction for Cognito and Supabase-backed user lookups."""

import json
from typing import Any, Dict, List, Optional
from urllib import request

from utils.powertools_compat import Logger, Tracer
from utils.service_contracts import (
    AUTH_PROVIDER,
    COGNITO_USER_POOL_ID,
    REGION as AWS_REGION,
    SUPABASE_SERVICE_ROLE_KEY,
    SUPABASE_URL,
)

LOG = Logger(serialize_stacktrace=False)
tracer = Tracer()

_cognito_client = None


def _get_cognito_client():
    global _cognito_client
    if _cognito_client is None:
        import boto3
        _cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)
    return _cognito_client


def _normalize_provider(provider: str) -> str:
    if provider in {"cognito", "supabase"}:
        return provider

    if provider == "auto":
        # Prefer Supabase when configured, otherwise default to Cognito.
        if SUPABASE_URL:
            return "supabase"
        return "cognito"

    return "cognito"


def _profile_from_cognito_user(user: Dict[str, Any]) -> Dict[str, Any]:
    user_id = ""
    email = ""
    name = ""
    email_verified = False

    for attr in user.get("Attributes", []):
        attr_name = attr.get("Name")
        attr_value = attr.get("Value")

        if attr_name == "sub":
            user_id = attr_value or ""
        elif attr_name == "email":
            email = attr_value or ""
        elif attr_name == "name":
            name = attr_value or ""
        elif attr_name == "email_verified":
            email_verified = str(attr_value).lower() == "true"

    username = user.get("Username") or email or name or user_id

    return {
        "user_id": user_id,
        "username": username,
        "email": email,
        "name": name,
        "enabled": bool(user.get("Enabled", False)),
        "status": user.get("UserStatus"),
        "email_verified": email_verified,
    }


def _profile_from_supabase_user(user: Dict[str, Any]) -> Dict[str, Any]:
    user_metadata = user.get("user_metadata") or {}
    if not isinstance(user_metadata, dict):
        user_metadata = {}

    identities = user.get("identities") or []
    identity_data = {}
    if identities and isinstance(identities, list):
        first_identity = identities[0] or {}
        identity_data = first_identity.get("identity_data") or {}
        if not isinstance(identity_data, dict):
            identity_data = {}

    user_id = str(user.get("id", "") or "")
    email = str(user.get("email", "") or "")
    name = (
        user_metadata.get("name")
        or user_metadata.get("full_name")
        or identity_data.get("name")
        or ""
    )
    username = (
        user_metadata.get("user_name")
        or user_metadata.get("username")
        or user_metadata.get("preferred_username")
        or name
        or email
        or user_id
    )

    return {
        "user_id": user_id,
        "username": str(username),
        "email": email,
        "name": str(name),
        "enabled": not bool(user.get("banned_until")),
        "status": "CONFIRMED" if user.get("email_confirmed_at") else "UNCONFIRMED",
        "email_verified": bool(user.get("email_confirmed_at")),
    }


def _build_supabase_admin_request(url: str) -> request.Request:
    return request.Request(
        url,
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "Content-Type": "application/json",
        },
    )


def _list_supabase_admin_users(max_results: int) -> List[Dict[str, Any]]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        LOG.warning(
            "Supabase admin user lookup skipped; missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY"
        )
        return []

    users: List[Dict[str, Any]] = []
    page = 1
    per_page = min(100, max_results)

    while len(users) < max_results:
        url = f"{SUPABASE_URL}/auth/v1/admin/users?page={page}&per_page={per_page}"
        req = _build_supabase_admin_request(url)

        with request.urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))

        page_users = payload.get("users") or []
        if not page_users:
            break

        users.extend(page_users)

        if len(page_users) < per_page:
            break
        page += 1

    return users[:max_results]


@tracer.capture_method
def get_user_profile(user_id: str) -> Dict[str, Any]:
    """Resolve a user profile with provider-aware lookup and resilient fallback."""
    provider = _normalize_provider(AUTH_PROVIDER)

    if provider == "supabase":
        try:
            users = _list_supabase_admin_users(max_results=1000)
            for user in users:
                if str(user.get("id", "")) == user_id:
                    return _profile_from_supabase_user(user)
        except Exception as e:
            LOG.warning("Supabase user lookup failed", user_id=user_id, error=str(e))

        return {
            "user_id": user_id,
            "username": user_id,
            "email": "",
            "name": "",
            "enabled": True,
            "status": None,
            "email_verified": False,
        }

    if not COGNITO_USER_POOL_ID:
        return {
            "user_id": user_id,
            "username": user_id,
            "email": "",
            "name": "",
            "enabled": True,
            "status": None,
            "email_verified": False,
        }

    try:
        response = _get_cognito_client().list_users(
            UserPoolId=COGNITO_USER_POOL_ID,
            Filter=f'sub = "{user_id}"',
            Limit=1,
        )
        if response.get("Users"):
            profile = _profile_from_cognito_user(response["Users"][0])
            if not profile.get("user_id"):
                profile["user_id"] = user_id
            return profile
    except Exception as e:
        LOG.warning("Cognito user lookup failed", user_id=user_id, error=str(e))

    return {
        "user_id": user_id,
        "username": user_id,
        "email": "",
        "name": "",
        "enabled": True,
        "status": None,
        "email_verified": False,
    }


@tracer.capture_method
def list_directory_users(
    search_filter: Optional[str] = None,
    max_results: int = 100,
    exclude_user: Optional[str] = None,
) -> Dict[str, Any]:
    """List users from configured directory provider with normalized response shape."""
    provider = _normalize_provider(AUTH_PROVIDER)

    users: List[Dict[str, Any]] = []

    if provider == "supabase":
        try:
            lowered_filter = (search_filter or "").strip().lower()
            for user in _list_supabase_admin_users(max_results=max_results * 3):
                profile = _profile_from_supabase_user(user)
                if exclude_user and profile.get("user_id") == exclude_user:
                    continue

                if lowered_filter:
                    haystack = " ".join(
                        [
                            str(profile.get("email") or ""),
                            str(profile.get("name") or ""),
                            str(profile.get("username") or ""),
                            str(profile.get("user_id") or ""),
                        ]
                    ).lower()
                    if lowered_filter not in haystack:
                        continue

                users.append(profile)
                if len(users) >= max_results:
                    break
        except Exception as e:
            LOG.error("Error listing Supabase users", error=str(e))
            raise

        return {"users": users[:max_results]}

    if not COGNITO_USER_POOL_ID:
        return {"users": []}

    pagination_token = None
    while len(users) < max_results:
        params: Dict[str, Any] = {
            "UserPoolId": COGNITO_USER_POOL_ID,
            "Limit": min(60, max_results - len(users)),
        }

        if pagination_token:
            params["PaginationToken"] = pagination_token

        if search_filter:
            params["Filter"] = f'email ^= "{search_filter}"'

        response = _get_cognito_client().list_users(**params)

        for user in response.get("Users", []):
            profile = _profile_from_cognito_user(user)
            if exclude_user and profile.get("user_id") == exclude_user:
                continue
            users.append(profile)

        pagination_token = response.get("PaginationToken")
        if not pagination_token:
            break

    return {"users": users[:max_results]}
