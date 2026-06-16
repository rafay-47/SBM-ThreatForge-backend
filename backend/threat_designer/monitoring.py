"""Monitoring and observability utilities."""

import logging
import os
import threading
import time
from contextlib import contextmanager
from typing import Any, Generator, Optional

import structlog
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from constants import (
    ENV_LOG_LEVEL,
    ENV_THREAT_DESIGNER_STDOUT_LLM_CALLS,
    ENV_TRACEBACK_ENABLED,
    ERROR_DYNAMODB_OPERATION_FAILED,
    ERROR_MODEL_INIT_FAILED,
    ERROR_S3_OPERATION_FAILED,
    ERROR_VALIDATION_FAILED,
)
from exceptions import ThreatModelingError

log_level_str = os.environ.get(ENV_LOG_LEVEL, "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(log_level))
logger = structlog.get_logger()


@contextmanager
def operation_context(operation_name: str, job_id: str) -> Generator[None, None, None]:
    """Context manager for operation monitoring."""
    start_time = time.time()
    logger.debug("Operation started", operation=operation_name, job_id=job_id)
    try:
        yield
        duration = time.time() - start_time
        logger.debug(
            "Operation completed",
            operation=operation_name,
            job_id=job_id,
            duration=duration,
        )
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            "Operation failed",
            operation=operation_name,
            job_id=job_id,
            duration=duration,
            error=str(e),
        )
        raise


def with_error_context(operation_name: str):
    """Decorator to add error context to operations."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                show_traceback = (
                    os.environ.get(ENV_TRACEBACK_ENABLED, "false").lower() == "true"
                )
                error_str = str(e)
                logger.error(
                    "Error in operation",
                    operation=operation_name,
                    error=error_str,
                    exc_info=show_traceback,
                )

                # Use centralized error messages for consistent formatting
                error_message = _get_error_message_for_operation(
                    operation_name, error_str
                )
                raise ThreatModelingError(error_message)

        return wrapper

    return decorator


def _get_error_message_for_operation(operation_name: str, original_error: str) -> str:
    """Get appropriate error message based on operation type."""
    operation_lower = operation_name.lower()

    if "model" in operation_lower or "bedrock" in operation_lower:
        return f"{ERROR_MODEL_INIT_FAILED}: {original_error}"
    elif "dynamodb" in operation_lower or "database" in operation_lower:
        return f"{ERROR_DYNAMODB_OPERATION_FAILED}: {original_error}"
    elif "s3" in operation_lower or "bucket" in operation_lower:
        return f"{ERROR_S3_OPERATION_FAILED}: {original_error}"
    elif "validation" in operation_lower or "validate" in operation_lower:
        return f"{ERROR_VALIDATION_FAILED}: {original_error}"
    else:
        return f"Failed to {operation_name}: {original_error}"


# ---------------------------------------------------------------------------
# Token usage tracking
# ---------------------------------------------------------------------------


def _llm_calls_to_stdout() -> bool:
    return os.environ.get(ENV_THREAT_DESIGNER_STDOUT_LLM_CALLS, "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


class TokenUsageTracker(BaseCallbackHandler):
    """Thread-safe callback that accumulates token usage across all LLM calls.

    Attach to the LangGraph config via ``"callbacks": [tracker]``.
    After the graph completes, call :meth:`log_totals` to emit the summary.

    Emits ``LLM_CALL_COMPLETE`` at INFO after each completion (so logs appear during
    long runs, not only at the end). Set ``THREAT_DESIGNER_STDOUT_LLM_CALLS=true``
    for plain lines on stdout in addition to structured logs.
    """

    def __init__(self, job_id: Optional[str] = None) -> None:
        super().__init__()
        self.job_id = job_id
        self._lock = threading.Lock()
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0
        self.total_calls = 0
        self.llm_roundtrips = 0
        self.llm_wall_seconds = 0.0
        self._llm_start: Optional[float] = None

    def on_llm_start(self, *args: Any, **kwargs: Any) -> None:
        """Legacy LLM path; ChatOpenAI typically uses on_chat_model_* instead."""
        with self._lock:
            self._llm_start = time.perf_counter()

    def on_chat_model_start(self, *args: Any, **kwargs: Any) -> None:
        """Chat models (e.g. ChatOpenAI) may omit on_llm_start; start timer here too."""
        with self._lock:
            self._llm_start = time.perf_counter()

    # Called after every LLM invocation (including inside subgraphs / Send workers)
    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        call_wall = 0.0
        with self._lock:
            if self._llm_start is not None:
                call_wall = time.perf_counter() - self._llm_start
                self.llm_wall_seconds += call_wall
            self._llm_start = None
            self.llm_roundtrips += 1
            rt = self.llm_roundtrips
            cum = self.llm_wall_seconds
        jid = self.job_id or "unknown"
        logger.info(
            "LLM_CALL_COMPLETE",
            job_id=jid,
            llm_roundtrip=rt,
            last_call_seconds=round(call_wall, 3),
            cumulative_llm_seconds=round(cum, 3),
        )
        if _llm_calls_to_stdout():
            print(
                f"[LLM] job={jid} roundtrip={rt} last={call_wall:.2f}s "
                f"cumulative={cum:.2f}s",
                flush=True,
            )
        for gen_list in response.generations:
            for gen in gen_list:
                msg = getattr(gen, "message", None)
                usage = getattr(msg, "usage_metadata", None) if msg else None
                if not usage:
                    continue
                details = usage.get("input_token_details") or {}
                with self._lock:
                    self.total_calls += 1
                    self.input_tokens += usage.get("input_tokens", 0)
                    self.output_tokens += usage.get("output_tokens", 0)
                    self.cache_read_input_tokens += details.get("cache_read", 0)
                    self.cache_creation_input_tokens += details.get(
                        "cache_creation", 0
                    )

    @property
    def totals(self) -> dict:
        with self._lock:
            return {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "cache_read_input_tokens": self.cache_read_input_tokens,
                "cache_creation_input_tokens": self.cache_creation_input_tokens,
                "total_calls": self.total_calls,
                "llm_roundtrips": self.llm_roundtrips,
                "llm_wall_seconds": round(self.llm_wall_seconds, 3),
            }

    def log_totals(self, job_id: str) -> None:
        """Emit an INFO-level log with accumulated token usage."""
        t = self.totals
        denom = t["llm_roundtrips"] or t["total_calls"] or 0
        avg_s = t["llm_wall_seconds"] / denom if denom else 0.0
        logger.info(
            "Token usage summary",
            job_id=job_id,
            input_tokens=t["input_tokens"],
            output_tokens=t["output_tokens"],
            cache_read_input_tokens=t["cache_read_input_tokens"],
            cache_creation_input_tokens=t["cache_creation_input_tokens"],
            total_calls=t["total_calls"],
            llm_roundtrips=t["llm_roundtrips"],
            llm_wall_seconds=t["llm_wall_seconds"],
            avg_seconds_per_llm_call=round(avg_s, 3),
        )
