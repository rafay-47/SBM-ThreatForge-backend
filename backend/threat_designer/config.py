"""Configuration management for the Threat Designer Agent."""

import os

# Load .env file if present
try:
    from dotenv import load_dotenv
    _env_dirs = [
        os.path.join(os.path.dirname(__file__), ".env"),
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
    ]
    for _env_path in _env_dirs:
        if os.path.exists(_env_path):
            load_dotenv(_env_path, override=True)
            break
except ImportError:
    pass

from constants import (
    DEFAULT_MAX_EXECUTION_TIME_MINUTES,
    DEFAULT_MAX_RETRY,
    DEFAULT_SUMMARY_MAX_WORDS,
    ENV_AGENT_STATE_TABLE,
    ENV_MODEL_PROVIDER,
    MAX_EXECUTION_TIME_MINUTES,
    MAX_RETRY_COUNT,
    MAX_SUMMARY_WORDS,
    MIN_EXECUTION_TIME_MINUTES,
    MIN_RETRY_COUNT,
    MIN_SUMMARY_WORDS,
    MODEL_PROVIDER_BEDROCK,
)
from pydantic import Field
from pydantic_settings import BaseSettings


class ThreatModelingConfig(BaseSettings):
    """Configuration settings for threat modeling workflow."""

    agent_state_table: str = Field(default="agent_state", env=ENV_AGENT_STATE_TABLE)
    model_provider: str = Field(default=MODEL_PROVIDER_BEDROCK, env=ENV_MODEL_PROVIDER)
    max_retries: int = Field(
        default=DEFAULT_MAX_RETRY, ge=MIN_RETRY_COUNT, le=MAX_RETRY_COUNT
    )
    max_execution_time_minutes: int = Field(
        default=DEFAULT_MAX_EXECUTION_TIME_MINUTES,
        ge=MIN_EXECUTION_TIME_MINUTES,
        le=MAX_EXECUTION_TIME_MINUTES,
    )
    summary_max_words: int = Field(
        default=DEFAULT_SUMMARY_MAX_WORDS, ge=MIN_SUMMARY_WORDS, le=MAX_SUMMARY_WORDS
    )

    class Config:
        validate_assignment = True


config = ThreatModelingConfig()
