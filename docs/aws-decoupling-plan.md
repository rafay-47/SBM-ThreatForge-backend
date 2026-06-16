# Threat Designer — AWS Decoupling Plan

> **Goal:** Decouple the Threat Designer project from AWS services and enable fully local execution while preserving the existing AWS deployment.

---

## Table of Contents

1. [Current Architecture](#1-current-architecture)
2. [Target Architecture](#2-target-architecture)
3. [AWS Services Inventory](#3-aws-services-inventory)
4. [Backend Decoupling](#4-backend-decoupling)
5. [Frontend Decoupling](#5-frontend-decoupling)
6. [Infrastructure](#6-infrastructure)
7. [Model Provider Expansion](#7-model-provider-expansion)
8. [Data Migration](#8-data-migration)
9. [Effort Estimate](#9-effort-estimate)
10. [Risk Assessment](#10-risk-assessment)
11. [Implementation Phases](#11-implementation-phases)

---

## 1. Current Architecture

### 1.1 High-Level Flow

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Frontend   │────▶│   API Gateway   │────▶│   Lambda (app)   │
│  (React +    │     │   (REST API)    │     │                  │
│   Amplify)   │     └────────┬────────┘     └────────┬─────────┘
└──────┬──────┘              │                        │
       │                     │                        │
       │              ┌──────▼────────┐      ┌────────▼─────────┐
       │              │   Authorizer   │      │  Bedrock Agent   │
       │              │   (Lambda)     │      │  Core Runtime    │
       │              └───────────────┘      │  (Containers)    │
       │                                     └────────┬─────────┘
       │                                              │
       │                     ┌────────────────────────┼────────────────────┐
       │                     ▼                        ▼                    ▼
       │            ┌───────────────┐      ┌──────────────┐     ┌──────────────┐
       │            │   DynamoDB    │      │      S3      │     │   Cognito    │
       │            │  (11 tables)  │      │  (3 buckets) │     │  (User Pool) │
       │            └───────────────┘      └──────────────┘     └──────────────┘
       │
       │              ┌─────────────────────────────────────────┐
       └─────────────▶│        Bedrock Agent Core (Sentry)      │
                      │        (Direct from browser)            │
                      └─────────────────────────────────────────┘
```

### 1.2 Component Breakdown

| Component                 | Type      | Entry Point                      | Deployment                         |
| ------------------------- | --------- | -------------------------------- | ---------------------------------- |
| **Frontend**              | React SPA | `npm run dev` / Amplify hosting  | AWS Amplify (CloudFront)           |
| **API Layer**             | Lambda    | `lambda_handler(event, context)` | AWS Lambda via API Gateway         |
| **Authorizer**            | Lambda    | `lambda_handler(event, context)` | API Gateway Lambda Authorizer      |
| **Threat Designer Agent** | FastAPI   | `POST /invocations` (port 8080)  | Bedrock Agent Core (ECR container) |
| **Sentry Agent**          | FastAPI   | `POST /invocations` (port 8080)  | Bedrock Agent Core (ECR container) |
| **Stream Processor**      | Lambda    | `lambda_handler(event, context)` | DynamoDB Streams trigger           |

### 1.3 Backend Directory Structure

```
backend/
├── app/                    # API Gateway Lambda (REST API layer)
│   ├── index.py            # Lambda entry point
│   ├── routes/             # Route definitions (3 routers)
│   ├── services/           # Business logic (5 service files)
│   ├── utils/              # Helpers + authorization decorators
│   └── exceptions/         # Custom exception hierarchy
├── authorizer/             # Lambda Authorizer (JWT validation)
├── threat_designer/        # AI Agent #1 — Threat modeling (FastAPI container)
│   ├── agent.py            # FastAPI entry point
│   ├── workflow.py         # Main LangGraph StateGraph
│   ├── workflow_*.py       # Subgraphs (threats, flows, version, attack tree, space)
│   ├── model_utils.py      # Bedrock/OpenAI model initialization
│   ├── utils.py            # DynamoDB/S3 operations
│   └── ...
├── sentry/                 # AI Agent #2 — Interactive chat (FastAPI container)
│   ├── agent.py            # FastAPI entry point
│   ├── graph.py            # ReAct LangGraph workflow
│   ├── config.py           # BedrockSessionSaver, model config
│   ├── tools.py            # Custom LangChain tools
│   └── ...
├── stream_processor/       # DynamoDB Streams consumer
└── dependencies/           # Shared requirements
```

---

## 2. Target Architecture

### 2.1 High-Level Flow (Local)

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Frontend   │────▶│    FastAPI       │────▶│   Threat Designer│
│  (React +    │     │    (app)         │     │   Agent (FastAPI)│
│   OIDC)     │     │   :8000          │     │   :8001          │
└──────┬──────┘     └────────┬────────┘     └────────┬─────────┘
       │                     │                        │
       │              ┌──────▼────────┐               │
       │              │ JWT Middleware │               │
       │              │ (Authlib)     │               │
       │              └───────────────┘               │
       │                                             │
       │                     ┌───────────────────────┼────────────────────┐
       │                     ▼                       ▼                    ▼
       │            ┌───────────────┐      ┌──────────────┐     ┌──────────────┐
       │            │  PostgreSQL   │      │   MinIO /    │     │   Authlib /  │
       │            │  (12 tables)  │      │   Local FS   │     │   Keycloak   │
       │            └───────────────┘      └──────────────┘     └──────────────┘
       │
       │              ┌─────────────────────────────────────────┐
       └─────────────▶│        Sentry Agent (FastAPI)           │
                      │        :8002                            │
                      └─────────────────────────────────────────┘
```

### 2.2 Service Replacement Matrix

| AWS Service                | Local Replacement                       | Notes                                   |
| -------------------------- | --------------------------------------- | --------------------------------------- |
| **Lambda**                 | FastAPI/uvicorn                         | Same Python code, different entry point |
| **API Gateway**            | FastAPI routing                         | Built-in, no extra service needed       |
| **DynamoDB** (11 tables)   | PostgreSQL (12 tables)                  | SQLAlchemy ORM, Alembic migrations      |
| **S3** (3 buckets)         | MinIO or Local FS                       | MinIO provides S3-compatible API        |
| **Cognito**                | Authlib + JWT or Keycloak               | OIDC-compatible JWKS endpoint           |
| **Bedrock Agent Core**     | Direct HTTP to FastAPI                  | Simpler — no runtime abstraction needed |
| **Bedrock Runtime**        | LiteLLM / Ollama / OpenAI               | Any OpenAI-compatible endpoint          |
| **Bedrock Knowledge Base** | Local vector DB (Chroma, Qdrant)        | Embeddings via local models             |
| **Bedrock SessionSaver**   | LangGraph InMemorySaver / PostgresSaver | Built into LangGraph                    |
| **DynamoDB Streams**       | Application events / polling            | Simpler synchronous approach            |
| **SQS DLQ**                | In-process retry queue                  | Not needed for local execution          |
| **Amplify**                | Vite dev server / Nginx                 | Standard web hosting                    |
| **CloudFront**             | Nginx reverse proxy                     | Optional for local                      |
| **X-Ray**                  | OpenTelemetry                           | Industry standard                       |
| **CloudWatch Logs**        | Structured logging (structlog)          | Already partially used                  |

---

## 3. AWS Services Inventory

### 3.1 Complete Service List

| #   | Service                    | Resource Count             | Primary Purpose      | Decoupling Difficulty               |
| --- | -------------------------- | -------------------------- | -------------------- | ----------------------------------- |
| 1   | **Lambda**                 | 3 functions + 1 layer      | Serverless compute   | Medium — replace with FastAPI       |
| 2   | **DynamoDB**               | 11 tables + streams + GSIs | Primary data store   | High — query patterns differ        |
| 3   | **S3**                     | 3 buckets                  | Object storage       | Low — MinIO is S3-compatible        |
| 4   | **S3 Vectors**             | 1 bucket + 1 index         | Vector store for KB  | Medium — replace with Chroma/Qdrant |
| 5   | **API Gateway**            | 1 REST API                 | HTTP front-end       | Low — FastAPI handles this          |
| 6   | **Cognito**                | 1 user pool + client       | Authentication       | Medium — OIDC replacement           |
| 7   | **Amplify**                | 1 app + 1 branch           | Frontend hosting     | Low — any static host works         |
| 8   | **Bedrock**                | Multiple models            | LLM inference        | Low — already supports OpenAI       |
| 9   | **Bedrock Agent Core**     | 2 agent runtimes           | Containerized agents | Medium — direct HTTP calls          |
| 10  | **Bedrock Knowledge Base** | 1 KB + 1 data source       | Semantic search      | Medium — local RAG pipeline         |
| 11  | **ECR**                    | 2 repositories             | Container registry   | Low — Docker registry               |
| 12  | **SQS**                    | 1 DLQ                      | Dead letter queue    | Low — in-process retry              |
| 13  | **IAM**                    | 10+ roles                  | Access control       | N/A — always needed                 |
| 14  | **CloudWatch Logs**        | Log groups                 | Logging              | Low — structlog                     |
| 15  | **X-Ray**                  | Active tracing             | Distributed tracing  | Low — OpenTelemetry                 |
| 16  | **CloudFront**             | Via Amplify                | CDN                  | Low — Nginx                         |
| 17  | **STS**                    | Implicit                   | Token service        | N/A — not directly used             |

### 3.2 Coupling Heat Map

| Component                                 | AWS Services Used                        | Lines of AWS Code | Decoupling Effort           |
| ----------------------------------------- | ---------------------------------------- | ----------------- | --------------------------- |
| `app/index.py`                            | API Gateway, Lambda Powertools           | ~135              | Medium                      |
| `app/routes/*.py`                         | API Gateway (via Powertools)             | ~900              | Medium                      |
| `app/services/threat_designer_service.py` | DynamoDB (6), S3, Bedrock Agent Core     | ~1900             | **Very High**               |
| `app/services/attack_tree_service.py`     | DynamoDB (3), Bedrock Agent Core         | ~1500             | **Very High**               |
| `app/services/space_service.py`           | DynamoDB (4), S3, Bedrock Agent, Cognito | ~400              | High                        |
| `app/services/collaboration_service.py`   | DynamoDB (4), S3, Cognito                | ~480              | High                        |
| `app/services/lock_service.py`            | DynamoDB (1), Cognito                    | ~415              | High                        |
| `authorizer/index.py`                     | Cognito (JWKS), API Gateway format       | ~85               | Medium                      |
| `threat_designer/model_utils.py`          | Bedrock Runtime                          | ~700              | Medium                      |
| `threat_designer/utils.py`                | DynamoDB (3), S3, Bedrock                | ~800              | High                        |
| `threat_designer/agent.py`                | S3, DynamoDB (indirect)                  | ~720              | Low-Medium                  |
| `threat_designer/workflow.py`             | LangGraph only                           | ~125              | **None** — already portable |
| `sentry/config.py`                        | Bedrock Runtime, BedrockSessionSaver     | ~180              | High                        |
| `sentry/graph.py`                         | Bedrock model, BedrockSessionSaver       | ~255              | High                        |
| `sentry/agent.py`                         | Bedrock Agent Core headers               | ~190              | Low-Medium                  |
| `sentry/session_manager.py`               | DynamoDB (1), BedrockSessionSaver        | ~145              | High                        |
| `sentry/history_manager.py`               | Bedrock Agent Runtime                    | ~245              | Medium                      |
| `sentry/tools.py`                         | DynamoDB (1)                             | ~185              | Low-Medium                  |
| `stream_processor/`                       | DynamoDB Streams                         | ~150              | Medium                      |

---

## 4. Backend Decoupling

### 4.1 Abstraction Layer

Create a common interfaces package that all services depend on instead of direct AWS SDK calls.

**New file: `backend/common/interfaces.py`**

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class QueryResult:
    items: List[Dict[str, Any]]
    last_evaluated_key: Optional[Dict[str, Any]] = None

class Database(ABC):
    """Abstract database interface replacing DynamoDB."""

    @abstractmethod
    async def get_item(self, table: str, key: Dict[str, Any]) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def put_item(self, table: str, item: Dict[str, Any]) -> None: ...

    @abstractmethod
    async def update_item(
        self, table: str, key: Dict[str, Any], data: Dict[str, Any],
        condition: Optional[str] = None
    ) -> Dict[str, Any]: ...

    @abstractmethod
    async def delete_item(
        self, table: str, key: Dict[str, Any],
        condition: Optional[str] = None
    ) -> None: ...

    @abstractmethod
    async def query(
        self, table: str, index_name: Optional[str],
        key_condition: Dict[str, Any],
        filter_expression: Optional[str] = None,
        projection: Optional[List[str]] = None,
        limit: Optional[int] = None,
        scan_forward: bool = True,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
    ) -> QueryResult: ...

    @abstractmethod
    async def scan(
        self, table: str, filter_expression: Optional[str] = None,
        limit: Optional[int] = None
    ) -> QueryResult: ...

    @abstractmethod
    async def batch_get_item(
        self, table: str, keys: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    async def batch_write_item(
        self, table: str, items: List[Dict[str, Any]]
    ) -> None: ...

class ObjectStorage(ABC):
    """Abstract storage interface replacing S3."""

    @abstractmethod
    async def get_object(self, bucket: str, key: str) -> bytes: ...

    @abstractmethod
    async def put_object(
        self, bucket: str, key: str, data: bytes,
        content_type: str = "application/octet-stream"
    ) -> str: ...

    @abstractmethod
    async def delete_object(self, bucket: str, key: str) -> None: ...

    @abstractmethod
    async def object_exists(self, bucket: str, key: str) -> bool: ...

    @abstractmethod
    async def generate_upload_url(
        self, bucket: str, key: str, content_type: str,
        expires_in: int = 300
    ) -> str: ...

    @abstractmethod
    async def generate_download_url(
        self, bucket: str, key: str, expires_in: int = 300
    ) -> str: ...

class UserDirectory(ABC):
    """Abstract user directory replacing Cognito."""

    @abstractmethod
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]: ...

    @abstractmethod
    async def list_users(
        self, search_filter: Optional[str] = None,
        limit: int = 100, pagination_token: Optional[str] = None
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_jwks_url(self) -> str: ...

    @abstractmethod
    def get_user_pool_id(self) -> str: ...

class AgentRuntime(ABC):
    """Abstract agent runtime replacing Bedrock Agent Core."""

    @abstractmethod
    async def invoke(
        self, session_id: str, payload: Dict[str, Any],
        endpoint: str
    ) -> Dict[str, Any]: ...

    @abstractmethod
    async def stop_session(self, session_id: str, endpoint: str) -> None: ...

class SessionStore(ABC):
    """Abstract session store replacing BedrockSessionSaver."""

    @abstractmethod
    async def create_session(self, session_id: str) -> str: ...

    @abstractmethod
    async def get_state(self, session_id: str, limit: int = 1) -> List[Any]: ...

    @abstractmethod
    async def save_state(self, session_id: str, state: Any) -> None: ...

    @abstractmethod
    async def delete_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def list_sessions(self) -> Dict[str, str]: ...
```

### 4.2 Factory Pattern

**New file: `backend/common/factory.py`**

```python
import os

def get_database():
    mode = os.getenv("DEPLOYMENT_MODE", "local")
    if mode == "aws":
        from common.aws_impl import DynamoDBImpl
        return DynamoDBImpl()
    from common.postgres_impl import PostgresImpl
    return PostgresImpl()

def get_storage():
    mode = os.getenv("DEPLOYMENT_MODE", "local")
    storage_type = os.getenv("STORAGE_TYPE", "local")
    if mode == "aws" or storage_type == "s3":
        from common.aws_impl import S3Impl
        return S3Impl()
    if storage_type == "minio":
        from common.minio_impl import MinIOImpl
        return MinIOImpl()
    from common.local_storage_impl import LocalStorageImpl
    return LocalStorageImpl()

def get_user_directory():
    mode = os.getenv("DEPLOYMENT_MODE", "local")
    auth_type = os.getenv("AUTH_TYPE", "local")
    if mode == "aws":
        from common.aws_impl import CognitoImpl
        return CognitoImpl()
    if auth_type == "keycloak":
        from common.keycloak_impl import KeycloakImpl
        return KeycloakImpl()
    from common.local_auth_impl import LocalAuthImpl
    return LocalAuthImpl()

def get_agent_runtime():
    mode = os.getenv("DEPLOYMENT_MODE", "local")
    if mode == "aws":
        from common.aws_impl import BedrockAgentCoreImpl
        return BedrockAgentCoreImpl()
    from common.local_agent_runtime import LocalAgentRuntime
    return LocalAgentRuntime()

def get_session_store():
    mode = os.getenv("DEPLOYMENT_MODE", "local")
    if mode == "aws":
        from common.aws_impl import BedrockSessionStore
        return BedrockSessionStore()
    from common.memory_session_store import InMemorySessionStore
    return InMemorySessionStore()
```

### 4.3 Replace `app/index.py` (Lambda → FastAPI)

**Current:**

```python
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.event_handler import APIGatewayRestResolver

app = APIGatewayRestResolver(serializer=custom_serializer, cors=cors_config)

@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    log_event(event)
    return add_security_headers(app.resolve(event, context))
```

**Target:**

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

logger = structlog.get_logger()

app = FastAPI(
    title="Threat Designer API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=trusted_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request, call_next):
    logger.info("request_started", method=request.method, path=request.url.path)
    response = await call_next(request)
    return response
```

### 4.4 Replace Route Decorators

**Current (`app/routes/threat_designer_route.py`):**

```python
from aws_lambda_powertools.event_handler.api_gateway import Router

router = Router()

@router.get("/threat-designer/<id>")
def get_threat_model(id: str):
    user_id = router.current_event.request_context.authorizer.get("user_id")
    body = threat_designer_service.fetch_results(id, AGENT_TABLE)
    return Response(status_code=200, content_type=content_types.APPLICATION_JSON, body=json.dumps(body))
```

**Target:**

```python
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/threat-designer/{id}")
async def get_threat_model(id: str, request: Request):
    user_id = request.state.user_id  # Set by auth middleware
    body = await threat_designer_service.fetch_results(id)
    return JSONResponse(status_code=200, content=body)
```

### 4.5 Replace Service Layer

This is the largest effort (~5,200 lines across 5 service files). Every `boto3` call must be replaced with interface methods.

#### 4.5.1 `threat_designer_service.py` (~1,900 lines)

| Current Pattern                                               | Target Pattern                                              |
| ------------------------------------------------------------- | ----------------------------------------------------------- |
| `boto3.resource("dynamodb").Table(STATE).update_item(...)`    | `db.update_item("state", {"id": job_id}, data)`             |
| `boto3.client("s3").generate_presigned_url(...)`              | `storage.generate_upload_url(bucket, key, content_type)`    |
| `boto3.client("bedrock-agentcore").invoke_agent_runtime(...)` | `agent_runtime.invoke(session_id, payload, endpoint)`       |
| `dynamodb.query(IndexName="owner-timestamp-index", ...)`      | `db.query("state", "owner-timestamp-index", key_condition)` |
| `dynamodb.batch_get_item(...)`                                | `db.batch_get_item("state", keys)`                          |

#### 4.5.2 `attack_tree_service.py` (~1,500 lines)

Same pattern as above. All validation functions (`validate_attack_tree_structure`, `validate_react_flow_format`, `detect_circular_dependency`) are pure Python and require **zero changes**.

#### 4.5.3 `space_service.py` (~400 lines)

Additional replacement for Bedrock Knowledge Base ingestion:

| Current Pattern                                 | Target Pattern                               |
| ----------------------------------------------- | -------------------------------------------- |
| `bedrock_agent_client.start_ingestion_job(...)` | `vector_store.ingest_documents(bucket, key)` |
| `bedrock_agent_client.list_ingestion_jobs(...)` | `vector_store.get_ingestion_status(job_id)`  |

#### 4.5.4 `collaboration_service.py` (~480 lines)

| Current Pattern                                         | Target Pattern                      |
| ------------------------------------------------------- | ----------------------------------- |
| `cognito_client.list_users(UserPoolId=..., Filter=...)` | `user_directory.list_users(filter)` |

#### 4.5.5 `lock_service.py` (~415 lines)

| Current Pattern                                                       | Target Pattern                                          |
| --------------------------------------------------------------------- | ------------------------------------------------------- |
| `dynamodb.Table(LOCKS_TABLE).put_item(Item={..., "ttl": expires_at})` | `db.put_item("locks", {..., "expires_at": expires_at})` |

Lock TTL logic must be implemented as:

- PostgreSQL: `expires_at` column + application-level stale check
- Scheduled cleanup job (pg_cron or Celery beat)

### 4.6 Replace Authorizer

**Current (`authorizer/index.py`):**

```python
def lambda_handler(event, context):
    token = event["authorizationToken"]
    keys_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    # ... validate and return API Gateway IAM policy
    return generate_policy(user_id, "Allow", event["methodArn"])
```

**Target (FastAPI middleware):**

```python
from authlib.jose import jwt, JsonWebKey
import httpx

async def verify_jwt(request: Request, call_next):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "Missing token"})

    token = auth_header[7:]
    jwks_url = user_directory.get_jwks_url()
    jwks = await fetch_jwks(jwks_url)

    try:
        claims = jwt.decode(token, jwks, claims_options={"aud": {"essential": True, "values": [client_id]}})
        claims.validate()
        request.state.user_id = claims["sub"]
        request.state.email = claims.get("email")
    except Exception:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})

    return await call_next(request)
```

### 4.7 Replace Threat Designer Agent

#### 4.7.1 `model_utils.py` (~700 lines)

Current supports Bedrock and OpenAI. Add two more providers:

```python
def initialize_models(config):
    provider = config.model_provider
    if provider == "bedrock":
        return _initialize_bedrock_models(config)
    elif provider == "openai":
        return _initialize_openai_models(config)
    elif provider == "ollama":
        return _initialize_ollama_models(config)
    elif provider == "litellm":
        return _initialize_litellm_models(config)
    else:
        raise ValueError(f"Unknown model provider: {provider}")

def _initialize_ollama_models(config):
    from langchain_community.chat_models import ChatOllama
    # Map each role to an Ollama model
    return {
        "assets": ChatOllama(model=config.ollama_asset_model, base_url=config.ollama_base_url),
        "flows": ChatOllama(model=config.ollama_flow_model, base_url=config.ollama_base_url),
        "threats": ChatOllama(model=config.ollama_threat_model, base_url=config.ollama_base_url),
        # ... etc
    }

def _initialize_litellm_models(config):
    from langchain_openai import ChatOpenAI
    # LiteLLM provides an OpenAI-compatible endpoint for 100+ providers
    return {
        "assets": ChatOpenAI(
            model=config.litellm_asset_model,
            api_key=config.litellm_api_key,
            base_url=config.litellm_base_url,
        ),
        # ... etc
    }
```

#### 4.7.2 `utils.py` (~800 lines)

Replace all `boto3` calls:

```python
# BEFORE
def _get_dynamodb():
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb", region_name=REGION)
    return _dynamodb_resource

def update_job_state(job_id, state, ...):
    dynamodb = _get_dynamodb()
    table = dynamodb.Table(JOB_STATUS_TABLE)
    table.update_item(Key={"id": job_id}, UpdateExpression="SET #state = :state", ...)

# AFTER
_db = None
def _get_db():
    global _db
    if _db is None:
        _db = get_database()  # From factory.py
    return _db

async def update_job_state(job_id, state, ...):
    db = _get_db()
    await db.update_item("job_status", {"id": job_id}, {"state": state, "timestamp": utc_now()})
```

#### 4.7.3 `agent.py` (~720 lines)

The FastAPI entry point is already portable. Changes needed:

- Remove `S3_BUCKET` and `AGENT_TABLE` env var references — use factory functions
- Replace `fetch_results()` and `parse_s3_image_to_base64()` calls with interface methods
- The background thread pattern (`ThreadPoolExecutor`) stays as-is

### 4.8 Replace Sentry Agent

#### 4.8.1 `config.py` (~180 lines)

```python
# BEFORE
from langgraph_checkpoint_aws.async_saver import AsyncBedrockSessionSaver
from langgraph_checkpoint_aws.saver import BedrockSessionSaver
from botocore.session import get_session

checkpointer = AsyncBedrockSessionSaver()
sync_checkpointer = BedrockSessionSaver()

# AFTER
from langgraph.checkpoint.memory import MemorySaver
# Or for persistence:
# from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

checkpointer = MemorySaver()  # In-memory, good for local dev
# checkpointer = AsyncPostgresSaver.from_conn_string(DATABASE_URL)  # For persistence
```

#### 4.8.2 `graph.py` (~255 lines)

```python
# BEFORE
from langchain_aws import ChatBedrockConverse
from langgraph_checkpoint_aws.async_saver import AsyncBedrockSessionSaver

def create_react_agent(model: ChatBedrockConverse, checkpointer: AsyncBedrockSessionSaver, ...):

# AFTER
from langchain_core.language_models import BaseChatModel
from langgraph.checkpoint.base import BaseCheckpointSaver

def create_react_agent(model: BaseChatModel, checkpointer: BaseCheckpointSaver, ...):
```

Remove Bedrock-specific cache points:

```python
# BEFORE
def _add_cache_point_if_bedrock(messages):
    messages.append({"cachePoint": {"type": "default"}})

# AFTER — only add if using a provider that supports prompt caching
def _add_cache_point_if_supported(messages, provider):
    if provider in ("bedrock", "anthropic"):
        messages.append({"cachePoint": {"type": "default"}})
```

#### 4.8.3 `session_manager.py` (~145 lines)

```python
# BEFORE
self.dynamodb = boto3.resource("dynamodb", region_name=REGION)
self.table = self.dynamodb.Table(TABLE_NAME)
# ... DynamoDB scan, get_item, put_item

# AFTER
self.db = get_database()
# ... db.scan(), db.get_item(), db.put_item()
```

#### 4.8.4 `history_manager.py` (~245 lines)

```python
# BEFORE
bedrock_agent = boto3.client("bedrock-agent-runtime", region_name=REGION)

def delete_bedrock_session(session_id):
    bedrock_agent.end_session(sessionIdentifier=session_id)
    bedrock_agent.delete_session(sessionIdentifier=session_id)

# AFTER
def delete_session(session_id):
    session_store = get_session_store()
    session_store.delete_session(session_id)
```

#### 4.8.5 `agent.py` (~190 lines)

Replace Bedrock-specific header:

```python
# BEFORE
session_id = request.headers.get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id")

# AFTER
session_id = request.headers.get("X-Session-Id")
```

### 4.9 Remove Stream Processor

The stream processor listens to DynamoDB Streams on `AGENT_STATE_TABLE` and deletes orphaned attack trees when threats are removed from a threat model.

**Option A — Inline deletion (simplest):**

Move the orphan cleanup logic into the `update_results()` and `delete_tm()` functions in `threat_designer_service.py`. When a threat model is updated, compute the threat diff and delete orphaned attack trees synchronously.

**Option B — Background task:**

Use FastAPI's `BackgroundTasks` or a Celery worker:

```python
from fastapi import BackgroundTasks

@app.put("/threat-designer/{id}")
async def update_threat_model(id: str, payload: dict, background_tasks: BackgroundTasks):
    # ... update logic
    background_tasks.add_task(cleanup_orphaned_attack_trees, old_threats, new_threats)
    return {"status": "ok"}
```

**Option C — PostgreSQL NOTIFY/LISTEN:**

```sql
CREATE OR REPLACE FUNCTION notify_threat_change() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('threat_changed', json_build_object('job_id', NEW.job_id, 'old_threats', OLD.threats, 'new_threats', NEW.threats)::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER threat_change_trigger
    AFTER UPDATE ON state
    FOR EACH ROW
    EXECUTE FUNCTION notify_threat_change();
```

Then a background worker listens and cleans up orphans.

---

## 5. Frontend Decoupling

### 5.1 Current Frontend AWS Dependencies

| File                                                           | AWS Import                                                            | Usage                            | Lines Affected |
| -------------------------------------------------------------- | --------------------------------------------------------------------- | -------------------------------- | -------------- |
| `src/config.js`                                                | `@aws-amplify/ui-react/styles.css`                                    | Amplify CSS                      | 1              |
| `src/bootstrap.jsx`                                            | `Amplify` from `aws-amplify`                                          | App initialization               | 1              |
| `src/services/Auth/auth.js`                                    | `signInWithRedirect`, `getCurrentUser`, `fetchAuthSession`, `signOut` | All auth operations              | ~60            |
| `src/components/Auth/LoginForm.jsx`                            | `signIn`, `confirmSignIn`, `resetPassword`, `confirmResetPassword`    | Login flows                      | ~200           |
| `src/services/ThreatDesigner/stats.jsx`                        | `fetchAuthSession`                                                    | Token for API calls              | ~10            |
| `src/services/ThreatDesigner/lockService.js`                   | `fetchAuthSession`                                                    | Token for lock operations        | ~5             |
| `src/services/ThreatDesigner/attackTreeService.js`             | `fetchAuthSession`                                                    | Token for attack tree ops        | ~5             |
| `src/services/Spaces/spacesService.js`                         | `fetchAuthSession`                                                    | Token for Spaces ops + S3 upload | ~15            |
| `src/components/Agent/context/api.js`                          | None direct, but uses Bedrock URL                                     | Bedrock AgentCore calls          | ~150           |
| `src/components/Agent/context/constants.js`                    | None direct                                                           | Hardcoded Bedrock URL            | ~10            |
| `src/components/Agent/context/utils.js`                        | `fetchAuthSession`                                                    | Token extraction                 | ~10            |
| `src/pages/Landingpage/Landingpage.jsx`                        | `getCurrentUser`, `Amplify`                                           | User check                       | ~5             |
| `src/pages/Spaces/SpacesCatalog.jsx`                           | `fetchAuthSession`                                                    | Token for user search            | ~5             |
| `src/components/ThreatModeling/SharingModal.jsx`               | `fetchAuthSession`                                                    | Token for sharing                | ~5             |
| `src/components/ThreatModeling/hooks/useAttackTreeMetadata.js` | `fetchAuthSession`                                                    | Token for metadata               | ~5             |

**Total:** 13 files with `fetchAuthSession` imports, 1 file with hardcoded Bedrock URL, 1 file with Amplify bootstrap.

### 5.2 Auth Adapter Pattern

**New file: `src/services/Auth/adapter.js`**

```javascript
// Auth adapter interface — swap implementations without changing consumers

export const authAdapter = {
  /**
   * Initialize the auth provider (called once at app startup)
   */
  async init(config) { ... },

  /**
   * Sign in with username/password
   */
  async signIn(username, password) { ... },

  /**
   * Sign out current user
   */
  async signOut() { ... },

  /**
   * Get current user info
   * @returns {{ user_id: string, email: string, name: string }}
   */
  async getUser() { ... },

  /**
   * Get a valid JWT access token (refreshes if expired)
   * @returns {string} Bearer token
   */
  async getAuthToken() { ... },

  /**
   * Force token refresh
   */
  async validateUser() { ... },
}
```

**Cognito implementation (current behavior):**

```javascript
// src/services/Auth/adapters/cognito.js
import { signInWithRedirect, getCurrentUser, fetchAuthSession, signOut } from "@aws-amplify/auth";

export const cognitoAdapter = {
  async init(config) {
    /* Amplify already configured in bootstrap */
  },
  async signIn(username, password) {
    /* redirect to Cognito */
  },
  async signOut() {
    return signOut();
  },
  async getUser() {
    const user = await getCurrentUser();
    const session = await fetchAuthSession();
    return {
      user_id: session.tokens.idToken.payload.sub,
      email: session.tokens.idToken.payload.email,
      name: session.tokens.idToken.payload.name,
    };
  },
  async getAuthToken() {
    const session = await fetchAuthSession();
    return session.tokens.accessToken.toString();
  },
  async validateUser() {
    await fetchAuthSession({ forceRefresh: true });
  },
};
```

**Generic OIDC implementation (target):**

```javascript
// src/services/Auth/adapters/oidc.js
import { UserManager } from "oidc-client-ts";

let userManager;

export const oidcAdapter = {
  async init(config) {
    userManager = new UserManager({
      authority: config.issuer,
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: "code",
      scope: "openid profile email",
    });
  },
  async signIn() {
    await userManager.signinRedirect();
  },
  async signOut() {
    await userManager.signoutRedirect();
  },
  async getUser() {
    const user = await userManager.getUser();
    return {
      user_id: user.profile.sub,
      email: user.profile.email,
      name: user.profile.name,
    };
  },
  async getAuthToken() {
    const user = await userManager.getUser();
    if (user.expired) {
      const refreshed = await userManager.signinSilent();
      return refreshed.access_token;
    }
    return user.access_token;
  },
  async validateUser() {
    await userManager.signinSilent();
  },
};
```

**Select adapter at runtime:**

```javascript
// src/services/Auth/index.js
import { cognitoAdapter } from "./adapters/cognito";
import { oidcAdapter } from "./adapters/oidc";

const provider = import.meta.env.VITE_AUTH_PROVIDER || "cognito";
export const auth = provider === "oidc" ? oidcAdapter : cognitoAdapter;
```

### 5.3 Replace All `fetchAuthSession` Imports

Every file that currently does:

```javascript
import { fetchAuthSession } from "aws-amplify/auth";
// ...
const session = await fetchAuthSession();
const token = session.tokens?.idToken?.toString();
```

Becomes:

```javascript
import { auth } from "../../services/Auth";
// ...
const token = await auth.getAuthToken();
```

**Affected files (13 total):**

1. `src/services/ThreatDesigner/stats.jsx`
2. `src/services/ThreatDesigner/lockService.js`
3. `src/services/ThreatDesigner/attackTreeService.js`
4. `src/services/Spaces/spacesService.js`
5. `src/components/Agent/context/utils.js`
6. `src/pages/Landingpage/Landingpage.jsx`
7. `src/pages/Spaces/SpacesCatalog.jsx`
8. `src/components/ThreatModeling/SharingModal.jsx`
9. `src/components/ThreatModeling/hooks/useAttackTreeMetadata.js`
10. `src/services/Auth/auth.js` (rewrite entirely)
11. `src/components/Auth/LoginForm.jsx` (rewrite entirely)
12. `src/bootstrap.jsx` (replace `Amplify.configure`)
13. `src/config.js` (remove Amplify config)

### 5.4 Replace Login Form

**Current:** Deeply coupled to Cognito's SRP auth, challenge-response, and confirmation code flows.

**Target:** Standard OAuth2/OIDC redirect flow or resource owner password grant.

```javascript
// BEFORE (Cognito-specific)
import { signIn, confirmSignIn, resetPassword, confirmResetPassword } from "aws-amplify/auth";

const handleLogin = async () => {
  const result = await signIn({ username, password });
  if (result.nextStep.signInStep === "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED") {
    await confirmSignIn({ challengeResponse: newPassword });
  }
};

// AFTER (Generic)
import { auth } from "../../services/Auth";

const handleLogin = async () => {
  await auth.signIn(username, password);
  // OIDC handles challenge flows internally
};
```

### 5.5 Replace Bedrock AgentCore Endpoint

**Current (`src/components/Agent/context/constants.js`):**

```javascript
const buildEndpoint = (path) =>
  `https://bedrock-agentcore.${import.meta.env.VITE_COGNITO_REGION}.amazonaws.com/runtimes/${import.meta.env.VITE_APP_SENTRY}/${path}?qualifier=DEFAULT`;
```

**Target:**

```javascript
const buildEndpoint = (path) => `${import.meta.env.VITE_SENTRY_API_URL}/${path}`;
```

**Current (`src/components/Agent/context/api.js`):**

```javascript
headers["X-Amzn-Bedrock-AgentCore-Runtime-Session-Id"] = sessionId;
```

**Target:**

```javascript
headers["X-Session-Id"] = sessionId;
```

### 5.6 Abstract File Storage

**Current (S3 presigned URL upload in `spacesService.js`):**

```javascript
// Step 1: Get presigned URL
const { presigned_url } = await api.post(`/spaces/${id}/documents/upload`, {
  file_name,
  content_type,
});
// Step 2: Direct PUT to S3
await fetch(presigned_url, {
  method: "PUT",
  body: file,
  headers: { "Content-Type": content_type },
});
// Step 3: Confirm
await api.post(`/spaces/${id}/documents/confirm`, { document_id, metadata });
```

**Target (Generic upload):**

```javascript
// Option A: Multipart form upload through backend
const formData = new FormData();
formData.append("file", file);
formData.append("metadata", JSON.stringify(metadata));
await api.post(`/spaces/${id}/documents/upload`, formData, {
  headers: { "Content-Type": "multipart/form-data" },
});

// Option B: Keep presigned URL pattern (works with MinIO too)
// The backend returns a presigned URL, frontend PUTs to it
// No frontend change needed — only backend changes
```

**Recommendation:** Keep the presigned URL pattern. MinIO supports the same presigned URL API as S3, so the frontend code doesn't need to change at all. Only rename `presigned_url` → `upload_url` for clarity.

### 5.7 Remove Amplify Dependencies

```bash
npm uninstall aws-amplify @aws-amplify/auth @aws-amplify/ui-react
npm install oidc-client-ts
```

Remove from `src/config.js`:

```javascript
// DELETE this line:
import "@aws-amplify/ui-react/styles.css";
```

Update `src/bootstrap.jsx`:

```javascript
// BEFORE
import { Amplify } from "aws-amplify";
import { amplifyConfig } from "./config";
Amplify.configure(amplifyConfig);

// AFTER
import { auth } from "./services/Auth";
await auth.init(authConfig);
```

### 5.8 Environment Variables

**Current (`.env`):**

```
VITE_APP_ENDPOINT=https://xxx.execute-api.us-east-1.amazonaws.com/dev
VITE_COGNITO_REGION=us-east-1
VITE_APP_SENTRY=arn:aws:bedrock-agentcore:...
```

**Target (`.env.local`):**

```
VITE_API_URL=http://localhost:8000
VITE_SENTRY_API_URL=http://localhost:8002
VITE_AUTH_PROVIDER=oidc
VITE_AUTH_ISSUER=http://localhost:8080/realms/threat-designer
VITE_AUTH_CLIENT_ID=threat-designer-web
VITE_AUTH_REDIRECT_URI=http://localhost:5173/callback
```

---

## 6. Infrastructure

### 6.1 Docker Compose

**New file: `docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: threat_designer
      POSTGRES_USER: td
      POSTGRES_PASSWORD: td_local_dev
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U td"]
      interval: 5s
      timeout: 3s
      retries: 5

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin123
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - miniodata:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 3s
      retries: 5

  minio-init:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set local http://minio:9000 minioadmin minioadmin123;
      mc mb local/architectures || true;
      mc mb local/spaces || true;
      mc mb local/lambda-artifacts || true;
      "

  backend-api:
    build:
      context: .
      dockerfile: backend/app/Dockerfile
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    environment:
      DEPLOYMENT_MODE: local
      DATABASE_URL: postgresql+asyncpg://td:td_local_dev@postgres:5432/threat_designer
      STORAGE_TYPE: minio
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin123
      MODEL_PROVIDER: openai
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      AUTH_TYPE: local
      JWT_SECRET: local-dev-secret-key-change-in-production
      JWT_ISSUER: http://localhost:8000
      THREAT_DESIGNER_AGENT_URL: http://agent-threat-designer:8001
      SENTRY_AGENT_URL: http://agent-sentry:8002
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy
    volumes:
      - ./backend/app:/app/backend/app
      - ./backend/threat_designer:/app/backend/threat_designer
      - ./backend/sentry:/app/backend/sentry

  agent-threat-designer:
    build:
      context: .
      dockerfile: backend/threat_designer/Dockerfile
    command: uvicorn agent:app --host 0.0.0.0 --port 8001 --reload
    environment:
      DEPLOYMENT_MODE: local
      DATABASE_URL: postgresql+asyncpg://td:td_local_dev@postgres:5432/threat_designer
      STORAGE_TYPE: minio
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin123
      MODEL_PROVIDER: openai
      OPENAI_API_KEY: ${OPENAI_API_KEY}
    ports:
      - "8001:8001"
    depends_on:
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy

  agent-sentry:
    build:
      context: .
      dockerfile: backend/sentry/Dockerfile
    command: uvicorn agent:app --host 0.0.0.0 --port 8002 --reload
    environment:
      DEPLOYMENT_MODE: local
      DATABASE_URL: postgresql+asyncpg://td:td_local_dev@postgres:5432/threat_designer
      MODEL_PROVIDER: openai
      OPENAI_API_KEY: ${OPENAI_API_KEY}
    ports:
      - "8002:8002"
    depends_on:
      postgres:
        condition: service_healthy

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend
    command: npm run dev -- --host 0.0.0.0
    environment:
      VITE_API_URL: http://localhost:8000
      VITE_SENTRY_API_URL: http://localhost:8002
      VITE_AUTH_PROVIDER: oidc
      VITE_AUTH_ISSUER: http://localhost:8080/realms/threat-designer
      VITE_AUTH_CLIENT_ID: threat-designer-web
      VITE_AUTH_REDIRECT_URI: http://localhost:5173/callback
    ports:
      - "5173:5173"
    volumes:
      - ./src:/app/src
      - ./public:/app/public
      - ./package.json:/app/package.json
      - ./vite.config.js:/app/vite.config.js
    depends_on:
      - backend-api
      - agent-sentry

  # Optional: Keycloak for production-ready auth
  # keycloak:
  #   image: quay.io/keycloak/keycloak:24.0
  #   command: start-dev
  #   environment:
  #     KEYCLOAK_ADMIN: admin
  #     KEYCLOAK_ADMIN_PASSWORD: admin
  #     KC_DB: postgres
  #     KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
  #     KC_DB_USERNAME: td
  #     KC_DB_PASSWORD: td_local_dev
  #   ports:
  #     - "8080:8080"
  #   depends_on:
  #     - postgres

volumes:
  pgdata:
  miniodata:
```

### 6.2 Database Schema

**New directory: `migrations/`**

Using Alembic for PostgreSQL migrations. Table mapping from DynamoDB:

#### 6.2.1 Core Tables

```sql
-- State table (threat_designer_state)
CREATE TABLE state (
    id UUID PRIMARY KEY,
    state VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry INT DEFAULT 0,
    session_id UUID,
    execution_owner VARCHAR(255),
    detail TEXT,
    cancelled BOOLEAN DEFAULT FALSE,
    is_shared BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_state_owner_timestamp ON state (execution_owner, timestamp DESC);

-- Job status table (threat_designer_status)
CREATE TABLE job_status (
    job_id UUID PRIMARY KEY,
    state VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry INT DEFAULT 0,
    detail TEXT,
    session_id UUID,
    execution_owner VARCHAR(255),
    cancelled BOOLEAN DEFAULT FALSE
);

-- Trail table (threat_designer_trail)
CREATE TABLE trail (
    id UUID PRIMARY KEY,
    assets JSONB,
    flows JSONB,
    threats JSONB,
    gaps JSONB,
    space_context TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agent table (attack_tree_data — stores completed threat models)
CREATE TABLE agent (
    job_id UUID PRIMARY KEY,
    title TEXT,
    description TEXT,
    summary TEXT,
    assets JSONB,
    system_architecture JSONB,
    threat_list JSONB,
    assumptions JSONB,
    s3_location TEXT,
    image_type TEXT,
    owner VARCHAR(255) NOT NULL,
    retry INT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_modified_at TIMESTAMPTZ,
    last_modified_by VARCHAR(255),
    content_hash VARCHAR(64),
    application_type VARCHAR(50),
    token_usage JSONB,
    space_insights JSONB,
    parent_id UUID,
    space_id UUID,
    is_shared BOOLEAN DEFAULT FALSE,
    backup JSONB
);

CREATE INDEX idx_agent_owner_timestamp ON agent (owner, timestamp DESC);
CREATE INDEX idx_agent_space_id ON agent (space_id);

-- Backup table (threat_designer_backup)
CREATE TABLE backup (
    job_id UUID PRIMARY KEY,
    data JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sharing table (threat_designer_sharing)
CREATE TABLE sharing (
    threat_model_id UUID NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    access_level VARCHAR(20) NOT NULL DEFAULT 'READ_ONLY',
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shared_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (threat_model_id, user_id)
);

CREATE INDEX idx_sharing_user_timestamp ON sharing (user_id, shared_at DESC);

-- Locks table (threat_designer_locks)
CREATE TABLE locks (
    threat_model_id UUID PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    token UUID NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_locks_expires ON locks (expires_at);
```

#### 6.2.2 Attack Tree Tables

```sql
-- Attack trees table
CREATE TABLE attack_trees (
    attack_tree_id UUID PRIMARY KEY,
    threat_model_id UUID NOT NULL,
    threat_name TEXT NOT NULL,
    stride_category VARCHAR(50),
    likelihood VARCHAR(20),
    tree_data JSONB,
    state VARCHAR(50) NOT NULL DEFAULT 'pending',
    owner VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_modified_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX idx_attack_trees_threat_model ON attack_trees (threat_model_id);
CREATE INDEX idx_attack_trees_state ON attack_trees (state);
```

#### 6.2.3 Spaces Tables

```sql
-- Spaces table
CREATE TABLE spaces (
    space_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    owner VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_spaces_owner ON spaces (owner);

-- Space sharing table
CREATE TABLE space_sharing (
    space_id UUID NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    access_level VARCHAR(20) NOT NULL DEFAULT 'READ_ONLY',
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shared_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (space_id, user_id)
);

-- Space documents table
CREATE TABLE space_documents (
    document_id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    file_name TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    content_type TEXT,
    file_size BIGINT,
    metadata JSONB,
    uploaded_by VARCHAR(255) NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingestion_status VARCHAR(50) DEFAULT 'pending'
);

CREATE INDEX idx_space_documents_space ON space_documents (space_id);
```

#### 6.2.4 Users Table

```sql
-- Users table (replaces Cognito user pool lookups)
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    status VARCHAR(50) DEFAULT 'CONFIRMED',
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_username ON users (username);
```

#### 6.2.5 Sentry Session Table

```sql
-- Sentry sessions (replaces sentry_session DynamoDB table)
CREATE TABLE sentry_sessions (
    session_key VARCHAR(512) PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    user_sub VARCHAR(255) NOT NULL,
    threat_model_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sentry_sessions_user ON sentry_sessions (user_sub);
```

### 6.3 Environment Configuration

**New file: `.env.example`**

```bash
# ============================================================
# Deployment Mode
# ============================================================
# "aws" = use AWS services (Lambda, DynamoDB, S3, Cognito, Bedrock)
# "local" = use local services (FastAPI, PostgreSQL, MinIO, Authlib)
DEPLOYMENT_MODE=local

# ============================================================
# Database
# ============================================================
DATABASE_URL=postgresql+asyncpg://td:td_local_dev@localhost:5432/threat_designer

# ============================================================
# Storage
# ============================================================
# "local" = filesystem, "minio" = MinIO (S3-compatible), "s3" = AWS S3
STORAGE_TYPE=minio

# MinIO configuration
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin123

# Local filesystem storage (if STORAGE_TYPE=local)
STORAGE_PATH=./data/files

# S3 configuration (if STORAGE_TYPE=s3)
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# ============================================================
# Authentication
# ============================================================
# "local" = Authlib + JWT, "keycloak" = Keycloak OIDC, "cognito" = AWS Cognito
AUTH_TYPE=local

# JWT configuration (for AUTH_TYPE=local)
JWT_SECRET=your-secret-key-change-in-production
JWT_ISSUER=http://localhost:8000
JWT_ALGORITHM=HS256
JWT_EXPIRY_SECONDS=3600

# Keycloak configuration (for AUTH_TYPE=keycloak)
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=threat-designer
KEYCLOAK_CLIENT_ID=threat-designer-web
KEYCLOAK_CLIENT_SECRET=

# Cognito configuration (for AUTH_TYPE=cognito)
COGNITO_REGION=us-east-1
COGNITO_USER_POOL_ID=
COGNITO_APP_CLIENT_ID=

# ============================================================
# AI Model Provider
# ============================================================
# "bedrock" = AWS Bedrock, "openai" = OpenAI API,
# "ollama" = local Ollama, "litellm" = LiteLLM proxy
MODEL_PROVIDER=openai

# OpenAI configuration
OPENAI_API_KEY=sk-...

# Ollama configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_ASSET_MODEL=qwen2.5:72b
OLLAMA_FLOW_MODEL=qwen2.5:72b
OLLAMA_THREAT_MODEL=qwen2.5:72b
OLLAMA_GAP_MODEL=qwen2.5:72b
OLLAMA_SUMMARY_MODEL=qwen2.5:72b
OLLAMA_STRUCTURE_MODEL=qwen2.5:72b
OLLAMA_VERSION_MODEL=qwen2.5:72b
OLLAMA_ATTACK_TREE_MODEL=qwen2.5:72b
OLLAMA_SPACE_CONTEXT_MODEL=qwen2.5:72b

# LiteLLM configuration
LITELLM_BASE_URL=http://localhost:4000
LITELLM_API_KEY=
LITELLM_ASSET_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_FLOW_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_THREAT_MODEL=anthropic/claude-opus-4-20250514
LITELLM_GAP_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_SUMMARY_MODEL=anthropic/claude-haiku-4-20250514
LITELLM_STRUCTURE_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_VERSION_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_ATTACK_TREE_MODEL=anthropic/claude-sonnet-4-20250514
LITELLM_SPACE_CONTEXT_MODEL=anthropic/claude-sonnet-4-20250514

# ============================================================
# Agent Endpoints (local mode)
# ============================================================
THREAT_DESIGNER_AGENT_URL=http://localhost:8001
SENTRY_AGENT_URL=http://localhost:8002

# ============================================================
# Sentry (Optional)
# ============================================================
ENABLE_SENTRY=true
TAVILY_API_KEY=tvly-...

# ============================================================
# Logging
# ============================================================
LOG_LEVEL=INFO
LOG_FORMAT=json
TRACEBACK_ENABLED=false
```

### 6.4 Frontend Environment

**New file: `.env.local` (frontend)**

```bash
VITE_API_URL=http://localhost:8000
VITE_SENTRY_API_URL=http://localhost:8002

# Auth configuration
VITE_AUTH_PROVIDER=oidc
VITE_AUTH_ISSUER=http://localhost:8080/realms/threat-designer
VITE_AUTH_CLIENT_ID=threat-designer-web
VITE_AUTH_REDIRECT_URI=http://localhost:5173/callback
VITE_AUTH_POST_LOGOUT_URI=http://localhost:5173/
```

---

## 7. Model Provider Expansion

### 7.1 Provider Comparison

| Provider    | Local?  | Cost          | Models                | Reasoning          | Setup Complexity             |
| ----------- | ------- | ------------- | --------------------- | ------------------ | ---------------------------- |
| **Bedrock** | No      | Pay-per-token | Claude 4.x family     | Adaptive thinking  | AWS account + model access   |
| **OpenAI**  | No      | Pay-per-token | GPT-5.x family        | Built-in reasoning | API key                      |
| **Ollama**  | Yes     | Free (GPU)    | Any open-weight model | Varies by model    | Install Ollama + pull models |
| **LiteLLM** | Partial | Varies        | 100+ providers        | Varies             | Deploy LiteLLM proxy         |
| **vLLM**    | Yes     | Free (GPU)    | Any open-weight model | Varies             | Deploy vLLM server           |

### 7.2 Ollama Integration

**Add to `backend/threat_designer/model_utils.py`:**

```python
def _initialize_ollama_models(config):
    """Initialize models using Ollama (local LLM server)."""
    from langchain_community.chat_models import ChatOllama

    base_url = config.ollama_base_url or "http://localhost:11434"
    models = {}

    role_model_map = {
        "assets": config.ollama_asset_model or "qwen2.5:72b",
        "flows": config.ollama_flow_model or "qwen2.5:72b",
        "threats": config.ollama_threat_model or "qwen2.5:72b",
        "gaps": config.ollama_gap_model or "qwen2.5:72b",
        "summary": config.ollama_summary_model or "qwen2.5:72b",
        "struct": config.ollama_structure_model or "qwen2.5:72b",
        "version": config.ollama_version_model or "qwen2.5:72b",
        "attack_tree": config.ollama_attack_tree_model or "qwen2.5:72b",
        "space_context": config.ollama_space_context_model or "qwen2.5:72b",
    }

    for role, model_name in role_model_map.items():
        models[role] = ChatOllama(
            model=model_name,
            base_url=base_url,
            temperature=0,
            num_ctx=32768,
        )

    return models
```

### 7.3 LiteLLM Integration

LiteLLM provides an OpenAI-compatible proxy for 100+ model providers (Anthropic, Google, Mistral, etc.).

```python
def _initialize_litellm_models(config):
    """Initialize models using LiteLLM proxy (OpenAI-compatible endpoint)."""
    from langchain_openai import ChatOpenAI

    base_url = config.litellm_base_url or "http://localhost:4000"
    models = {}

    for role, model_id in config.litellm_role_models.items():
        models[role] = ChatOpenAI(
            model=model_id,
            api_key=config.litellm_api_key,
            base_url=base_url,
            temperature=0,
            max_tokens=config.max_tokens.get(role, 64000),
        )

    return models
```

### 7.4 Reasoning Mode Mapping

| UI Level | Bedrock (Adaptive) | Bedrock (Budget)    | OpenAI                  | Ollama |
| -------- | ------------------ | ------------------- | ----------------------- | ------ |
| Off      | N/A                | budget_tokens=0     | reasoning_effort=off    | N/A    |
| Low      | effort=low         | budget_tokens=1024  | reasoning_effort=low    | N/A    |
| Medium   | effort=medium      | budget_tokens=4096  | reasoning_effort=medium | N/A    |
| High     | effort=high        | budget_tokens=16384 | reasoning_effort=high   | N/A    |
| Max      | effort=max         | budget_tokens=32768 | N/A                     | N/A    |

For Ollama and other open-weight models, reasoning is not a configurable parameter — it depends on the model architecture. Models like `qwen2.5:72b` have built-in reasoning capabilities that are always active.

---

## 8. Data Migration

### 8.1 AWS → Local Migration Script

For existing AWS deployments that want to migrate to local:

```python
# scripts/migrate_aws_to_local.py
"""
Migrate data from AWS (DynamoDB + S3) to local (PostgreSQL + MinIO).

Usage:
    python migrate_aws_to_local.py --aws-profile myprofile --region us-east-1
"""

import asyncio
import boto3
import asyncpg
from minio import Minio

async def migrate():
    # Connect to AWS
    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    s3 = boto3.client("s3", region_name=args.region)

    # Connect to local PostgreSQL
    conn = await asyncpg.connect(DATABASE_URL)

    # Migrate each table
    for aws_table, pg_table in TABLE_MAPPING.items():
        await migrate_table(dynamodb.Table(aws_table), conn, pg_table)

    # Migrate S3 objects to MinIO
    minio_client = Minio(MINIO_ENDPOINT, access_key=..., secret_key=...)
    await migrate_s3_bucket(s3, minio_client, args.source_bucket, args.target_bucket)

async def migrate_table(dynamodb_table, pg_conn, pg_table):
    """Scan DynamoDB table and insert into PostgreSQL."""
    scan_kwargs = {}
    while True:
        response = dynamodb_table.scan(**scan_kwargs)
        for item in response["Items"]:
            # Convert DynamoDB types to Python types
            pg_item = convert_dynamodb_to_pg(item)
            # Insert into PostgreSQL
            columns = ", ".join(pg_item.keys())
            values = ", ".join(["$" + str(i+1) for i in range(len(pg_item))])
            await pg_conn.execute(
                f"INSERT INTO {pg_table} ({columns}) VALUES ({values}) "
                f"ON CONFLICT DO NOTHING",
                *pg_item.values()
            )
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
```

### 8.2 Type Conversion

| DynamoDB Type     | PostgreSQL Type             | Conversion                           |
| ----------------- | --------------------------- | ------------------------------------ |
| `S` (String)      | `TEXT`                      | Direct                               |
| `N` (Number)      | `NUMERIC` / `INT` / `FLOAT` | `decimal.Decimal` → appropriate type |
| `BOOL`            | `BOOLEAN`                   | Direct                               |
| `NULL`            | `NULL`                      | Direct                               |
| `L` (List)        | `JSONB`                     | Serialize to JSON                    |
| `M` (Map)         | `JSONB`                     | Serialize to JSON                    |
| `SS` (String Set) | `TEXT[]` or `JSONB`         | Convert to array                     |
| `NS` (Number Set) | `NUMERIC[]` or `JSONB`      | Convert to array                     |
| `BS` (Binary Set) | `BYTEA[]`                   | Convert to byte arrays               |
| `B` (Binary)      | `BYTEA`                     | Direct                               |

---

## 9. Effort Estimate

### 9.1 Phase Breakdown

| Phase                        | Scope                                            | Key Deliverables                                                                                                           | Effort    |
| ---------------------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | --------- |
| **1. Abstraction Layer**     | Interfaces, factory, implementations             | `interfaces.py`, `factory.py`, `postgres_impl.py`, `local_storage_impl.py`, `local_auth_impl.py`, `local_agent_runtime.py` | 2-3 weeks |
| **2. Backend API Layer**     | Lambda → FastAPI, routes, authorizer             | `app/main.py`, route refactoring (3 files), JWT middleware                                                                 | 1-2 weeks |
| **3. Backend Services**      | Replace all boto3 calls                          | 5 service files (~5,200 lines), authorization decorators                                                                   | 3-4 weeks |
| **4. Threat Designer Agent** | Model providers, utils, config                   | `model_utils.py` (add Ollama/LiteLLM), `utils.py` refactor, `config.py`                                                    | 1-2 weeks |
| **5. Sentry Agent**          | Checkpointer, session, history                   | `config.py`, `graph.py`, `session_manager.py`, `history_manager.py`, `tools.py`                                            | 1-2 weeks |
| **6. Stream Processor**      | Replace DynamoDB Streams                         | Inline cleanup or background task                                                                                          | 2-3 days  |
| **7. Frontend Auth**         | Replace Amplify, auth adapter                    | `adapter.js`, OIDC implementation, login form rewrite                                                                      | 1-2 weeks |
| **8. Frontend API**          | Replace fetchAuthSession (13 files), Bedrock URL | Token injection, endpoint config, header changes                                                                           | 3-5 days  |
| **9. Frontend Storage**      | Abstract presigned URLs                          | Upload/download abstraction (minimal change if MinIO)                                                                      | 2-3 days  |
| **10. Infrastructure**       | Docker Compose, migrations, env config           | `docker-compose.yml`, Alembic migrations, `.env.example`                                                                   | 1-2 weeks |
| **11. Testing**              | Unit, integration, E2E                           | Test suite for all components, regression testing                                                                          | 2-3 weeks |
| **12. Documentation**        | Setup guides, API docs                           | README updates, local dev guide, migration guide                                                                           | 3-5 days  |

### 9.2 Total Effort

| Scenario                                          | Timeline    | Team Size      |
| ------------------------------------------------- | ----------- | -------------- |
| **Aggressive** (parallel work, experienced team)  | 8-10 weeks  | 3-4 developers |
| **Realistic** (sequential phases, 1-2 developers) | 12-16 weeks | 1-2 developers |
| **Conservative** (part-time, learning curve)      | 16-24 weeks | 1 developer    |

### 9.3 Effort by Component

| Component                                 | Lines to Change | Complexity | Effort    |
| ----------------------------------------- | --------------- | ---------- | --------- |
| `app/services/threat_designer_service.py` | ~1,900          | Very High  | 2-3 weeks |
| `app/services/attack_tree_service.py`     | ~1,500          | High       | 1-2 weeks |
| `app/services/space_service.py`           | ~400            | High       | 3-5 days  |
| `app/services/collaboration_service.py`   | ~480            | Medium     | 3-5 days  |
| `app/services/lock_service.py`            | ~415            | Medium     | 3-5 days  |
| `app/routes/*.py` (3 files)               | ~900            | Medium     | 3-5 days  |
| `app/index.py`                            | ~135            | Medium     | 1-2 days  |
| `authorizer/index.py`                     | ~85             | Medium     | 1-2 days  |
| `threat_designer/model_utils.py`          | ~700            | Medium     | 3-5 days  |
| `threat_designer/utils.py`                | ~800            | High       | 1 week    |
| `threat_designer/agent.py`                | ~720            | Low        | 2-3 days  |
| `sentry/config.py`                        | ~180            | High       | 2-3 days  |
| `sentry/graph.py`                         | ~255            | High       | 2-3 days  |
| `sentry/session_manager.py`               | ~145            | High       | 2-3 days  |
| `sentry/history_manager.py`               | ~245            | Medium     | 2-3 days  |
| `sentry/tools.py`                         | ~185            | Low        | 1-2 days  |
| `sentry/agent.py`                         | ~190            | Low        | 1-2 days  |
| **Frontend (all files)**                  | ~600            | Medium     | 1-2 weeks |
| **Infrastructure**                        | New files       | Medium     | 1-2 weeks |

---

## 10. Risk Assessment

### 10.1 Technical Risks

| Risk                                            | Impact | Likelihood | Mitigation                                                                                                                                              |
| ----------------------------------------------- | ------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DynamoDB → PostgreSQL query mismatch**        | High   | Medium     | DynamoDB's query model (GSI, partition keys) differs from SQL. Complex pagination queries need careful rewriting. Test each query pattern individually. |
| **DynamoDB TTL → PostgreSQL cleanup**           | Medium | Low        | Implement scheduled cleanup job (pg_cron or Celery beat). Lock expiration must be checked at query time.                                                |
| **Bedrock Agent Core invocation pattern**       | High   | Low        | Direct HTTP to FastAPI is simpler than Bedrock Agent Core. The async background thread pattern in `agent.py` works identically.                         |
| **BedrockSessionSaver → LangGraph MemorySaver** | Medium | Low        | LangGraph has built-in `InMemorySaver`, `PostgresSaver`, `RedisSaver`. The API is compatible.                                                           |
| **Cognito JWT validation**                      | Medium | Low        | Use established OIDC libraries (Authlib, oidc-client-ts). Don't implement JWT validation from scratch.                                                  |
| **DynamoDB Streams replacement**                | Low    | Low        | Replace with application-level events. The stream processor only handles orphan cleanup — can be done inline.                                           |
| **S3 presigned URL compatibility**              | Low    | Low        | MinIO supports the same presigned URL API. Frontend code requires zero changes if using MinIO.                                                          |
| **LangGraph workflow compatibility**            | Low    | Low        | LangGraph workflows are cloud-agnostic. Only the checkpointer and model types need swapping.                                                            |
| **Performance regression**                      | Medium | Medium     | PostgreSQL may be slower for some access patterns. Add appropriate indexes. Use connection pooling (PgBouncer).                                         |
| **Breaking existing AWS deployment**            | High   | Medium     | Use feature flags (`DEPLOYMENT_MODE`) to support both. Run CI/CD against both configurations.                                                           |

### 10.2 Operational Risks

| Risk                                | Impact | Likelihood | Mitigation                                                                                                                                          |
| ----------------------------------- | ------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Local LLM quality**               | High   | High       | Open-weight models (Qwen, Llama) may produce lower-quality threat analysis than Claude. Provide clear model recommendations and quality benchmarks. |
| **GPU requirements for local LLMs** | Medium | High       | Ollama with 72B models needs ~48GB VRAM. Provide smaller model configurations (7B-14B) for machines without GPUs.                                   |
| **Docker resource requirements**    | Medium | Medium     | Full stack (PostgreSQL + MinIO + 3 FastAPI services + frontend) needs ~4GB RAM minimum. Document requirements.                                      |
| **Migration data loss**             | High   | Low        | Test migration scripts thoroughly. Keep AWS deployment as fallback until local is validated.                                                        |
| **Maintenance burden of dual-mode** | Medium | Medium     | Dual-mode adds complexity. Consider sunsetting AWS mode after local is proven stable.                                                               |

---

## 11. Implementation Phases

### Phase 1: Foundation (Weeks 1-3)

**Goal:** Create abstraction layer and run a minimal end-to-end flow locally.

1. Create `backend/common/interfaces.py` with all abstract classes
2. Create `backend/common/factory.py` with deployment mode routing
3. Implement `PostgresImpl` (Database interface) with SQLAlchemy
4. Implement `LocalStorageImpl` (ObjectStorage interface) with filesystem
5. Implement `LocalAgentRuntime` (AgentRuntime interface) with httpx
6. Create `docker-compose.yml` with PostgreSQL + MinIO
7. Create Alembic migrations for core tables (state, job_status, agent)
8. Modify `threat_designer/utils.py` to use `get_database()` instead of boto3
9. Test: Run threat designer agent locally with OpenAI + PostgreSQL

**Success criteria:** Can create a threat model via direct FastAPI call, data persists in PostgreSQL.

### Phase 2: Backend API (Weeks 4-6)

**Goal:** Replace Lambda/API Gateway with FastAPI, refactor all services.

1. Create `backend/app/main.py` as FastAPI app
2. Refactor all 3 route files to use FastAPI decorators
3. Create JWT verification middleware (replaces Lambda Authorizer)
4. Refactor `threat_designer_service.py` (~1,900 lines)
5. Refactor `attack_tree_service.py` (~1,500 lines)
6. Refactor `space_service.py`, `collaboration_service.py`, `lock_service.py`
7. Implement `LocalAuthImpl` with Authlib + JWT
8. Create users table and auth endpoints (login, register, JWKS)
9. Test: Full API test suite against local FastAPI

**Success criteria:** All API endpoints work locally with JWT auth, PostgreSQL, and local storage.

### Phase 3: Agents (Weeks 7-9)

**Goal:** Decouple both agents from AWS-specific dependencies.

1. Add Ollama and LiteLLM providers to `model_utils.py`
2. Replace `BedrockSessionSaver` with LangGraph `InMemorySaver`/`PostgresSaver`
3. Refactor `sentry/config.py`, `graph.py`, `session_manager.py`
4. Replace Bedrock-specific headers with generic session headers
5. Refactor `sentry/history_manager.py` to use LangGraph state history
6. Remove stream processor, replace with inline cleanup
7. Test: End-to-end threat modeling + Sentry chat locally

**Success criteria:** Both agents run as FastAPI services, support multiple model providers, persist sessions locally.

### Phase 4: Frontend (Weeks 10-12)

**Goal:** Replace Amplify/Cognito with generic OIDC auth.

1. Create auth adapter interface (`src/services/Auth/adapter.js`)
2. Implement OIDC adapter with `oidc-client-ts`
3. Replace all 13 `fetchAuthSession` imports with `auth.getAuthToken()`
4. Rewrite login form for standard OAuth2 flows
5. Replace Bedrock AgentCore URL with configurable endpoint
6. Replace `X-Amzn-Bedrock-AgentCore-*` header with `X-Session-Id`
7. Update environment variables and Vite config
8. Remove Amplify dependencies
9. Test: Full UI flow locally (login, create threat model, view results, Sentry chat)

**Success criteria:** Frontend runs with `npm run dev`, authenticates via local OIDC, communicates with local backend.

### Phase 5: Polish & Testing (Weeks 13-16)

**Goal:** Production-ready local deployment with comprehensive testing.

1. Write integration tests for all API endpoints
2. Write E2E tests for critical user journeys
3. Performance testing (PostgreSQL query optimization, connection pooling)
4. Documentation (local dev guide, migration guide, model recommendations)
5. Docker Compose hardening (health checks, resource limits, volumes)
6. CI/CD pipeline for both AWS and local modes
7. Migration script (AWS → Local)
8. Security audit (JWT validation, input validation, CORS)

**Success criteria:** `docker compose up` starts the full stack, all tests pass, documentation is complete.

---

## Appendix A: Files Requiring Changes

### Backend (24 files)

| File                                              | Lines  | Change Type    | Priority |
| ------------------------------------------------- | ------ | -------------- | -------- |
| `backend/common/interfaces.py`                    | New    | Create         | 1        |
| `backend/common/factory.py`                       | New    | Create         | 1        |
| `backend/common/postgres_impl.py`                 | New    | Create         | 1        |
| `backend/common/local_storage_impl.py`            | New    | Create         | 1        |
| `backend/common/local_auth_impl.py`               | New    | Create         | 2        |
| `backend/common/local_agent_runtime.py`           | New    | Create         | 2        |
| `backend/app/main.py`                             | New    | Create         | 2        |
| `backend/app/index.py`                            | ~135   | Rewrite        | 2        |
| `backend/app/routes/threat_designer_route.py`     | ~400   | Refactor       | 2        |
| `backend/app/routes/attack_tree_route.py`         | ~250   | Refactor       | 2        |
| `backend/app/routes/space_route.py`               | ~250   | Refactor       | 2        |
| `backend/app/services/threat_designer_service.py` | ~1,900 | Refactor       | 1        |
| `backend/app/services/attack_tree_service.py`     | ~1,500 | Refactor       | 1        |
| `backend/app/services/space_service.py`           | ~400   | Refactor       | 2        |
| `backend/app/services/collaboration_service.py`   | ~480   | Refactor       | 2        |
| `backend/app/services/lock_service.py`            | ~415   | Refactor       | 2        |
| `backend/app/utils/authorization.py`              | ~210   | Refactor       | 2        |
| `backend/authorizer/index.py`                     | ~85    | Replace        | 2        |
| `backend/threat_designer/model_utils.py`          | ~700   | Extend         | 2        |
| `backend/threat_designer/utils.py`                | ~800   | Refactor       | 1        |
| `backend/threat_designer/agent.py`                | ~720   | Modify         | 3        |
| `backend/threat_designer/config.py`               | ~40    | Modify         | 2        |
| `backend/threat_designer/constants.py`            | ~270   | Modify         | 2        |
| `backend/sentry/config.py`                        | ~180   | Refactor       | 2        |
| `backend/sentry/graph.py`                         | ~255   | Refactor       | 2        |
| `backend/sentry/agent.py`                         | ~190   | Modify         | 3        |
| `backend/sentry/session_manager.py`               | ~145   | Refactor       | 2        |
| `backend/sentry/history_manager.py`               | ~245   | Refactor       | 2        |
| `backend/sentry/tools.py`                         | ~185   | Refactor       | 3        |
| `backend/sentry/handlers.py`                      | ~95    | Modify         | 3        |
| `backend/stream_processor/`                       | ~150   | Remove/Replace | 3        |

### Frontend (15 files)

| File                                                           | Lines | Change Type | Priority |
| -------------------------------------------------------------- | ----- | ----------- | -------- |
| `src/services/Auth/adapter.js`                                 | New   | Create      | 1        |
| `src/services/Auth/adapters/cognito.js`                        | New   | Create      | 2        |
| `src/services/Auth/adapters/oidc.js`                           | New   | Create      | 1        |
| `src/services/Auth/index.js`                                   | New   | Create      | 1        |
| `src/config.js`                                                | ~30   | Modify      | 1        |
| `src/bootstrap.jsx`                                            | ~15   | Modify      | 1        |
| `src/services/Auth/auth.js`                                    | ~60   | Rewrite     | 1        |
| `src/components/Auth/LoginForm.jsx`                            | ~200  | Rewrite     | 1        |
| `src/services/ThreatDesigner/stats.jsx`                        | ~190  | Modify      | 2        |
| `src/services/ThreatDesigner/lockService.js`                   | ~115  | Modify      | 2        |
| `src/services/ThreatDesigner/attackTreeService.js`             | ~230  | Modify      | 2        |
| `src/services/Spaces/spacesService.js`                         | ~220  | Modify      | 2        |
| `src/components/Agent/context/constants.js`                    | ~15   | Modify      | 1        |
| `src/components/Agent/context/api.js`                          | ~150  | Modify      | 1        |
| `src/components/Agent/context/utils.js`                        | ~15   | Modify      | 2        |
| `src/pages/Landingpage/Landingpage.jsx`                        | ~50   | Modify      | 3        |
| `src/pages/Spaces/SpacesCatalog.jsx`                           | ~200  | Modify      | 3        |
| `src/components/ThreatModeling/SharingModal.jsx`               | ~120  | Modify      | 3        |
| `src/components/ThreatModeling/hooks/useAttackTreeMetadata.js` | ~50   | Modify      | 3        |
| `package.json`                                                 | ~60   | Modify      | 1        |

### Infrastructure (New files)

| File                              | Purpose                                |
| --------------------------------- | -------------------------------------- |
| `docker-compose.yml`              | Local development stack                |
| `docker-compose.prod.yml`         | Production local stack (with Keycloak) |
| `.env.example`                    | Environment variable template          |
| `migrations/versions/*.py`        | Alembic migration files                |
| `migrations/env.py`               | Alembic configuration                  |
| `backend/app/Dockerfile`          | FastAPI API Dockerfile                 |
| `Dockerfile.frontend`             | Frontend Dockerfile                    |
| `scripts/migrate_aws_to_local.py` | Data migration script                  |

---

## Appendix B: What Stays Unchanged

The following components are **fully cloud-agnostic** and require zero changes:

### Backend (Pure Python)

| Component                                     | Reason                                            |
| --------------------------------------------- | ------------------------------------------------- |
| `threat_designer/workflow.py`                 | LangGraph StateGraph — library, not AWS service   |
| `threat_designer/workflow_threats.py`         | ReAct subgraph — pure LangGraph                   |
| `threat_designer/workflow_flows.py`           | ReAct subgraph — pure LangGraph                   |
| `threat_designer/workflow_version.py`         | Subgraph — pure LangGraph                         |
| `threat_designer/workflow_attack_tree.py`     | Subgraph — pure LangGraph                         |
| `threat_designer/workflow_space_context.py`   | Subgraph — pure LangGraph                         |
| `threat_designer/nodes.py`                    | Business logic — pure Python                      |
| `threat_designer/state.py`                    | Pydantic models — pure Python                     |
| `threat_designer/models.py`                   | Pydantic models — pure Python                     |
| `threat_designer/prompts.py`                  | System prompts — pure text                        |
| `threat_designer/prompt_provider.py`          | Prompt assembly — pure Python                     |
| `threat_designer/attack_tree_prompts.py`      | Prompts — pure text                               |
| `threat_designer/attack_tree_models.py`       | Pydantic models — pure Python                     |
| `threat_designer/attack_tree_tools.py`        | LangChain tools — pure Python                     |
| `threat_designer/tools.py`                    | LangChain tools — pure Python                     |
| `threat_designer/partitioner.py`              | Asset partitioning — pure Python                  |
| `threat_designer/message_builder.py`          | Message construction — pure Python                |
| `threat_designer/monitoring.py`               | Logging — structlog (already portable)            |
| `threat_designer/exceptions.py`               | Custom exceptions — pure Python                   |
| `threat_designer/version_utils.py`            | Version diffing — pure Python                     |
| `sentry/graph.py` (logic)                     | ReAct pattern — pure LangGraph                    |
| `sentry/tools.py` (logic)                     | LangChain tools with interrupt() — pure LangGraph |
| `sentry/tavily_tools.py`                      | Tavily API — external service, not AWS            |
| `sentry/prompt.py`                            | System prompts — pure text                        |
| `sentry/models.py`                            | Pydantic models — pure Python                     |
| `sentry/data_model.py`                        | Data models — pure Python                         |
| `sentry/agent_manager.py`                     | Agent lifecycle — pure Python                     |
| `sentry/streaming.py`                         | SSE streaming — pure Python                       |
| `sentry/exceptions.py`                        | Custom exceptions — pure Python                   |
| `sentry/utils.py`                             | Utilities — pure Python                           |
| `app/exceptions/exceptions.py`                | Custom exceptions — pure Python                   |
| `attack_tree_service.py` validation functions | Pure business logic                               |

### Frontend (Pure JavaScript/React)

| Component                                    | Reason                                             |
| -------------------------------------------- | -------------------------------------------------- |
| Attack tree cache (`attackTreeCache.js`)     | Pure in-memory Map                                 |
| Presigned URL cache (`presignedUrlCache.js`) | Generic URL cache                                  |
| Session helpers (`sessionHelpers.js`)        | Pure message processing                            |
| Session seed (`sessionSeed.js`)              | Browser sessionStorage                             |
| S3Downloader component                       | Generic URL downloader (only naming references S3) |
| All React UI components                      | Framework-agnostic React                           |
| All CSS/styling                              | Framework-agnostic                                 |

---

## Appendix C: Quick Start (After Implementation)

```bash
# 1. Clone and configure
git clone <repo>
cd threat-designer
cp .env.example .env
# Edit .env with your OPENAI_API_KEY or configure Ollama

# 2. Start infrastructure
docker compose up -d postgres minio minio-init

# 3. Run migrations
cd backend
alembic upgrade head

# 4. Start all services
docker compose up -d backend-api agent-threat-designer agent-sentry frontend

# 5. Open browser
open http://localhost:5173

# Or for fully local AI (no cloud API keys):
# 1. Install Ollama: https://ollama.ai
# 2. Pull models: ollama pull qwen2.5:72b
# 3. Set MODEL_PROVIDER=ollama in .env
# 4. docker compose up -d
```
