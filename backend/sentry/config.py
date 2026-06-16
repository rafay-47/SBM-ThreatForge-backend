import os
import json
import logging
from typing import Optional, Any, Tuple

# Load .env file if present (same directory or parent)
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(_env_path):
        _env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    load_dotenv(_env_path, override=True)
except ImportError:
    pass

try:
    from langgraph.checkpoint.memory import MemorySaver
except ImportError:
    from langgraph.checkpoint.memory import InMemorySaver as MemorySaver

try:
    from langgraph_checkpoint_aws.async_saver import AsyncBedrockSessionSaver
    from langgraph_checkpoint_aws.saver import BedrockSessionSaver

    AWS_CHECKPOINTER_AVAILABLE = True
except ImportError:
    AsyncBedrockSessionSaver = None
    BedrockSessionSaver = None
    AWS_CHECKPOINTER_AVAILABLE = False


logger = logging.getLogger(__name__)

# Try to import OpenAI support
try:
    from langchain_openai import ChatOpenAI

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    ChatOpenAI = None

# Environment Configuration
MODEL_ID = os.environ.get("MODEL_ID")
S3_BUCKET = os.environ.get("S3_BUCKET")
REGION = os.environ.get("REGION", "us-east-1")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
OPENROUTER_BASE_URL = (
    os.environ.get("OPENROUTER_BASE_URL", "").strip() or "https://openrouter.ai/api/v1"
)
FIREWORKS_API_KEY = os.environ.get("FIREWORKS_API_KEY", "").strip()
FIREWORKS_BASE_URL = (
    os.environ.get("FIREWORKS_BASE_URL", "").strip()
    or "https://api.fireworks.ai/inference/v1"
)
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "64000"))
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "local").lower()

# Auto-select provider: default to openai in local mode, bedrock in AWS mode
_configured_provider = os.environ.get("MODEL_PROVIDER")
if _configured_provider:
    MODEL_PROVIDER = _configured_provider
elif DEPLOYMENT_MODE == "aws":
    MODEL_PROVIDER = "bedrock"
elif OPENROUTER_API_KEY:
    MODEL_PROVIDER = "openrouter"
elif FIREWORKS_API_KEY:
    MODEL_PROVIDER = "fireworks"
elif OPENAI_API_KEY:
    MODEL_PROVIDER = "openai"
else:
    MODEL_PROVIDER = "openai"  # safest default for local mode

# Default model IDs per provider (used when MODEL_ID is not set)
_DEFAULT_MODEL_IDS = {
    "bedrock": "anthropic.claude-sonnet-4-20250514-v1:0",
    "openai": "gpt-5-mini-2025-08-07",
    "openrouter": "accounts/fireworks/models/qwen3p6-plus",
    "fireworks": "accounts/fireworks/models/qwen3p6-plus",
}
if not MODEL_ID:
    MODEL_ID = _DEFAULT_MODEL_IDS.get(MODEL_PROVIDER, _DEFAULT_MODEL_IDS["openai"])

# Tavily Configuration
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")


# Parse reasoning budget/effort from environment
def _parse_reasoning_config() -> dict:
    """Parse reasoning budget/effort from environment"""
    if MODEL_PROVIDER in ("openai", "openrouter", "fireworks"):
        raw = os.environ.get(
            "REASONING_EFFORT",
            '{"0": "none", "1": "low", "2": "medium", "3": "high", "4": "xhigh"}',
        )
        return {int(k): v for k, v in json.loads(raw).items()}
    else:
        raw = os.environ.get("REASONING_BUDGET", '{"1": 16000, "2": 32000, "3": 63999}')
        return {int(k): int(v) for k, v in json.loads(raw).items()}


REASONING_CONFIG = _parse_reasoning_config()

# Adaptive thinking configuration
ADAPTIVE_THINKING_MODELS = json.loads(os.environ.get("ADAPTIVE_THINKING_MODELS", "[]"))
ADAPTIVE_EFFORT_MAP = {1: "low", 2: "medium", 3: "high", 4: "max"}

# Models that support "Max" reasoning level
MODELS_SUPPORTING_MAX = json.loads(os.environ.get("MODELS_SUPPORTING_MAX", "[]"))

# OpenAI reasoning effort mapping (fallback for backward compatibility)
OPENAI_REASONING_EFFORT_MAP = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "xhigh"}


# AWS Client (only when explicitly in AWS mode with Bedrock provider)
boto_client = None
if MODEL_PROVIDER == "bedrock" and DEPLOYMENT_MODE == "aws":
    try:
        from botocore.session import get_session
        from botocore.config import Config
        import boto3

        _bedrock_config = Config(read_timeout=1000)
        _session = get_session()
        boto_client = _session.create_client(
            service_name="bedrock-runtime", region_name=REGION, config=_bedrock_config
        )
    except Exception as e:
        logger.warning("Failed to create Bedrock client: %s", e)


def create_checkpointers() -> Tuple[Any, Any]:
    """Create checkpointers for the active deployment mode.

    In local mode we use an in-memory saver to keep thread history available
    without requiring AWS session infrastructure.
    """
    if DEPLOYMENT_MODE == "aws" and AWS_CHECKPOINTER_AVAILABLE:
        return AsyncBedrockSessionSaver(), BedrockSessionSaver()

    if DEPLOYMENT_MODE == "aws" and not AWS_CHECKPOINTER_AVAILABLE:
        logger.warning(
            "AWS deployment mode requested but langgraph-checkpoint-aws is unavailable. "
            "Falling back to in-memory checkpointer."
        )

    return MemorySaver(), None


# Checkpointer
checkpointer, sync_checkpointer = create_checkpointers()

# Available Tools
ALL_AVAILABLE_TOOLS = []


# Budget Level Configuration (uses REASONING_CONFIG from environment)
BUDGET_MAPPING = (
    REASONING_CONFIG if MODEL_PROVIDER == "bedrock" else {1: 16000, 2: 32000, 3: 63999}
)


def create_model_config(budget_level: int = 1) -> dict:
    """Create model configuration based on budget level and provider"""
    if MODEL_PROVIDER == "openai":
        return _create_openai_model_config(budget_level)
    elif MODEL_PROVIDER == "openrouter":
        return _create_openrouter_model_config(budget_level)
    elif MODEL_PROVIDER == "fireworks":
        return _create_fireworks_model_config(budget_level)
    else:
        return _create_bedrock_model_config(budget_level)


def _create_bedrock_model_config(budget_level: int = 1) -> dict:
    """Create Bedrock model configuration based on budget level"""
    # Cap level 4 (Max) to 3 (High) if model doesn't support Max
    if budget_level == 4 and MODEL_ID not in MODELS_SUPPORTING_MAX:
        budget_level = 3

    base_config = {
        "max_tokens": MAX_TOKENS,
        "model_id": MODEL_ID,
        "client": boto_client,
        "temperature": 0 if budget_level == 0 else 1,
    }

    # If budget_level is 0, don't add thinking at all
    if budget_level == 0:
        return base_config

    # Check if the model supports adaptive thinking
    if MODEL_ID in ADAPTIVE_THINKING_MODELS:
        effort = ADAPTIVE_EFFORT_MAP.get(budget_level, "low")
        base_config["additional_model_request_fields"] = {
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": effort},
        }
    else:
        # For standard models, level 4 falls back to level 3 budget
        budget_tokens = REASONING_CONFIG.get(
            budget_level, REASONING_CONFIG.get(3, 8000)
        )
        base_config["additional_model_request_fields"] = {
            "thinking": {
                "type": "enabled",
                "budget_tokens": budget_tokens,
            },
            "anthropic_beta": ["interleaved-thinking-2025-05-14"],
        }

    return base_config


def _create_openai_model_config(budget_level: int = 1) -> dict:
    """Create OpenAI model configuration based on budget level"""
    if not OPENAI_AVAILABLE:
        raise ImportError(
            "OpenAI provider requires langchain-openai package. "
            "Install with: pip install langchain-openai"
        )

    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY environment variable not set")

    base_config = {
        "model": MODEL_ID or "gpt-5-mini-2025-08-07",
        "max_tokens": MAX_TOKENS,
        "api_key": OPENAI_API_KEY,
        "temperature": 0,
        "use_responses_api": True,
        "streaming": True,
    }

    # Add reasoning effort if budget level > 0
    if budget_level > 0:
        reasoning_effort = REASONING_CONFIG.get(budget_level, "low")
        base_config["reasoning"] = {"effort": reasoning_effort, "summary": "detailed"}

    return base_config


def _create_openrouter_model_config(budget_level: int = 1) -> dict:
    """OpenRouter: OpenAI-compatible chat + optional reasoning (extra_body)."""
    if not OPENAI_AVAILABLE:
        raise ImportError(
            "OpenRouter provider requires langchain-openai package. "
            "Install with: pip install langchain-openai"
        )

    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY environment variable not set")

    base_config = {
        "model": MODEL_ID or "accounts/fireworks/models/qwen3p6-plus",
        "max_tokens": MAX_TOKENS,
        "api_key": OPENROUTER_API_KEY,
        "base_url": OPENROUTER_BASE_URL,
        "temperature": 0,
        "streaming": True,
    }

    default_headers = {}
    referer = os.environ.get("OPENROUTER_HTTP_REFERER", "").strip()
    site_title = os.environ.get("OPENROUTER_SITE_TITLE", "").strip()
    if referer:
        default_headers["HTTP-Referer"] = referer
    if site_title:
        default_headers["X-OpenRouter-Title"] = site_title
    if default_headers:
        base_config["default_headers"] = default_headers

    if os.environ.get("OPENROUTER_REASONING_ENABLED", "true").lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        base_config["extra_body"] = {"reasoning": {"enabled": True}}

    if budget_level > 0:
        logger.debug(
            "OpenRouter model config includes reasoning extra_body when enabled; "
            "budget_level %d is informational",
            budget_level,
        )

    return base_config


def _create_fireworks_model_config(budget_level: int = 1) -> dict:
    """Fireworks: OpenAI-compatible chat completions at api.fireworks.ai."""
    if not OPENAI_AVAILABLE:
        raise ImportError(
            "Fireworks provider requires langchain-openai package. "
            "Install with: pip install langchain-openai"
        )

    if not FIREWORKS_API_KEY:
        raise ValueError("FIREWORKS_API_KEY environment variable not set")

    raw_temp = os.environ.get("FIREWORKS_TEMPERATURE", "").strip()
    if raw_temp:
        try:
            temperature = float(raw_temp)
        except ValueError:
            temperature = 0
    else:
        temperature = 0

    base_config = {
        "model": MODEL_ID or "accounts/fireworks/models/qwen3p6-plus",
        "max_tokens": MAX_TOKENS,
        "api_key": FIREWORKS_API_KEY,
        "base_url": FIREWORKS_BASE_URL,
        "temperature": temperature,
        "streaming": True,
    }

    model_kwargs = {}
    for env_name, key in (
        ("FIREWORKS_TOP_P", "top_p"),
        ("FIREWORKS_TOP_K", "top_k"),
        ("FIREWORKS_PRESENCE_PENALTY", "presence_penalty"),
        ("FIREWORKS_FREQUENCY_PENALTY", "frequency_penalty"),
    ):
        raw = os.environ.get(env_name, "").strip()
        if not raw:
            continue
        try:
            if key == "top_k":
                model_kwargs[key] = int(float(raw))
            else:
                model_kwargs[key] = float(raw)
        except ValueError:
            pass
    if model_kwargs:
        base_config["model_kwargs"] = model_kwargs

    if budget_level > 0:
        logger.debug(
            "Fireworks model config: budget_level %d is informational for this provider",
            budget_level,
        )

    return base_config


def create_model(budget_level: int = 1) -> Any:
    """Create model instance based on provider"""
    config = create_model_config(budget_level)

    if MODEL_PROVIDER == "openai":
        return ChatOpenAI(**config)
    elif MODEL_PROVIDER == "openrouter":
        return ChatOpenAI(**config)
    elif MODEL_PROVIDER == "fireworks":
        return ChatOpenAI(**config)
    else:
        from langchain_aws import ChatBedrockConverse

        return ChatBedrockConverse(**config)
