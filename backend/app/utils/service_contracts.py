"""Centralized backend app service contracts.

This module defines normalized environment-driven contracts used by backend app
services so provider/backend migration (for example, to Supabase) touches fewer
files and keeps defaults consistent.
"""

from utils.env_defaults import get_deployment_mode, get_env, get_region

# Provider switches for future backend/storage migrations.
DATABASE_PROVIDER = get_env("DATABASE_PROVIDER", "aws").lower()
STORAGE_PROVIDER = get_env("STORAGE_PROVIDER", "aws").lower()
AUTH_PROVIDER = get_env("AUTH_PROVIDER", "cognito").lower()

# Shared runtime mode/region.
DEPLOYMENT_MODE = get_deployment_mode()
REGION = get_region()

# Core tables.
JOB_STATUS_TABLE = get_env("JOB_STATUS_TABLE", "job_status")
AGENT_STATE_TABLE = get_env("AGENT_STATE_TABLE", "agent_state")
ATTACK_TREE_TABLE = get_env("ATTACK_TREE_TABLE", "attack_trees")
BACKUP_TABLE = get_env("BACKUP_TABLE", "backup")
AGENT_TRAIL_TABLE = get_env("AGENT_TRAIL_TABLE", "agent_trail")
SHARING_TABLE = get_env("SHARING_TABLE", "sharing")
LOCKS_TABLE = get_env("LOCKS_TABLE", "locks")

# Spaces tables.
SPACES_TABLE = get_env("SPACES_TABLE", "spaces")
SPACE_SHARING_TABLE = get_env("SPACE_SHARING_TABLE", "space_sharing")
SPACE_DOCUMENTS_TABLE = get_env("SPACE_DOCUMENTS_TABLE", "space_documents")

# Storage buckets.
ARCHITECTURE_BUCKET = get_env("ARCHITECTURE_BUCKET", "architecture-bucket")
SPACES_BUCKET = get_env("SPACES_BUCKET", "spaces-bucket")

# Threat-modeling runtime config.
THREAT_MODELING_AGENT = get_env("THREAT_MODELING_AGENT")
THREAT_MODELING_AGENT_URL = get_env("THREAT_MODELING_AGENT_URL", "").rstrip("/")
THREAT_MODELING_AGENT_STOP_URL = get_env("THREAT_MODELING_AGENT_STOP_URL", "")

# Spaces KB ingestion config.
KNOWLEDGE_BASE_ID = get_env("KNOWLEDGE_BASE_ID", "")
KB_DATA_SOURCE_ID = get_env("KB_DATA_SOURCE_ID", "")
PRESIGNED_URL_EXPIRY = int(get_env("PRESIGNED_URL_EXPIRY", "900"))
ENABLE_SPACE_KB_INGESTION = (
    get_env("ENABLE_SPACE_KB_INGESTION", "true").lower() == "true"
)

# User directory config.
COGNITO_USER_POOL_ID = get_env("COGNITO_USER_POOL_ID", "")
SUPABASE_URL = get_env("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = get_env("SUPABASE_SERVICE_ROLE_KEY", "")

# Postgres (Supabase direct) — used for pgvector space RAG when SPACE_PGVECTOR is enabled.
DATABASE_URL = get_env("DATABASE_URL", "")

# Embeddings for space RAG (OpenRouter Nemotron VL by default in space_pgvector_service).
OPENROUTER_API_KEY = get_env("OPENROUTER_API_KEY", "")
