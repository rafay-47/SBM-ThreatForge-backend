"""
One-shot vision model call (OpenRouter or Fireworks) to describe architecture diagrams.

When MAIN_MODEL includes `architecture_vision` and MODEL_PROVIDER is openrouter or fireworks,
the diagram is sent to a VL model;
the text is stored on state as `architecture_diagram_text` so text-only models
never receive image_url blocks.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage
from monitoring import logger

from constants import (
    ENV_FIREWORKS_API_KEY,
    ENV_FIREWORKS_BASE_URL,
    ENV_MODEL_PROVIDER,
    ENV_OPENROUTER_API_KEY,
    ENV_OPENROUTER_BASE_URL,
    ENV_OPENROUTER_HTTP_REFERER,
    ENV_OPENROUTER_SITE_TITLE,
    FIREWORKS_BASE_URL_DEFAULT,
    MODEL_PROVIDER_FIREWORKS,
    MODEL_PROVIDER_OPENROUTER,
    OPENROUTER_BASE_URL_DEFAULT,
)

_VISION_PROMPT = """You are a senior security architect. Describe this architecture diagram in detail for downstream threat modeling.

Include, when visible:
- Major components, services, and data stores
- Trust boundaries and network zones
- External systems and user/entry points
- Data flows you can infer between labeled elements

Use clear structured prose. If something is unclear or not visible, say so. Do not invent components that are not shown."""

ENV_ARCHITECTURE_VISION_PREFLIGHT_WRITE_TEXT = (
    "ARCHITECTURE_VISION_PREFLIGHT_WRITE_TEXT"
)
ENV_ARCHITECTURE_VISION_PREFLIGHT_OUTPUT_DIR = (
    "ARCHITECTURE_VISION_PREFLIGHT_OUTPUT_DIR"
)
ENV_THREAT_DESIGNER_ENABLE_IMAGE_INPUTS = "THREAT_DESIGNER_ENABLE_IMAGE_INPUTS"


def _vision_disabled() -> bool:
    return os.environ.get("OPENROUTER_ARCHITECTURE_VISION_DISABLED", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _is_truthy(value: str) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _should_write_preflight_text() -> bool:
    return _is_truthy(os.environ.get(ENV_ARCHITECTURE_VISION_PREFLIGHT_WRITE_TEXT, ""))


def _image_inputs_enabled() -> bool:
    """If enabled, skip preflight and keep raw image inputs in prompts."""
    return _is_truthy(os.environ.get(ENV_THREAT_DESIGNER_ENABLE_IMAGE_INPUTS, ""))


def _safe_job_id(job_id: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in str(job_id))
    return cleaned or "unknown_job"


def _write_preflight_text_output(state: Dict[str, Any], job_id: str, model_id: str) -> None:
    if not _should_write_preflight_text():
        return

    output_dir_raw = (
        os.environ.get(ENV_ARCHITECTURE_VISION_PREFLIGHT_OUTPUT_DIR, "")
        or "architecture_vision_preflight_outputs"
    ).strip()
    output_dir = Path(output_dir_raw).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.now(timezone.utc).isoformat()
    is_version = bool(state.get("version"))
    sections = [
        f"generated_at_utc: {now_utc}",
        f"job_id: {job_id}",
        f"model_id: {model_id}",
        f"version_mode: {is_version}",
        "",
    ]

    if is_version:
        sections.extend(
            [
                "=== PREVIOUS ARCHITECTURE DIAGRAM TEXT ===",
                (state.get("previous_architecture_diagram_text") or "").strip()
                or "(empty)",
                "",
                "=== NEW ARCHITECTURE DIAGRAM TEXT ===",
                (state.get("architecture_diagram_text") or "").strip() or "(empty)",
                "",
            ]
        )
    else:
        sections.extend(
            [
                "=== ARCHITECTURE DIAGRAM TEXT ===",
                (state.get("architecture_diagram_text") or "").strip() or "(empty)",
                "",
            ]
        )

    filename = f"{_safe_job_id(job_id)}_architecture_vision_preflight.txt"
    output_path = output_dir / filename
    output_path.write_text("\n".join(sections), encoding="utf-8")

    logger.info(
        "Architecture vision preflight text output written",
        job_id=job_id,
        output_path=str(output_path),
    )


def _mime_from_image_type(image_type: Optional[str]) -> str:
    if not image_type:
        return "image/jpeg"
    lower = image_type.lower()
    if "png" in lower:
        return "image/png"
    if "jpeg" in lower or "jpg" in lower:
        return "image/jpeg"
    if "/" in lower:
        return lower
    return f"image/{lower}"


def _build_vision_chat_model(vision_config: Dict[str, Any]) -> Any:
    from langchain_openai import ChatOpenAI

    api_key = (os.environ.get(ENV_OPENROUTER_API_KEY) or "").strip()
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is required for architecture vision preflight")

    base_url = (
        os.environ.get(ENV_OPENROUTER_BASE_URL, "") or ""
    ).strip() or OPENROUTER_BASE_URL_DEFAULT

    default_headers: Dict[str, str] = {}
    referer = (os.environ.get(ENV_OPENROUTER_HTTP_REFERER, "") or "").strip()
    title = (os.environ.get(ENV_OPENROUTER_SITE_TITLE, "") or "").strip()
    if referer:
        default_headers["HTTP-Referer"] = referer
    if title:
        default_headers["X-OpenRouter-Title"] = title

    model_id = vision_config["id"]
    max_tokens = int(vision_config.get("max_tokens") or 100000)

    kwargs: Dict[str, Any] = {
        "model": model_id,
        "max_tokens": max_tokens,
        "temperature": 0,
        "api_key": api_key,
        "base_url": base_url,
    }
    if default_headers:
        kwargs["default_headers"] = default_headers
    # VL models: do not send OpenRouter reasoning extra_body (Stepfun-style)

    return ChatOpenAI(**kwargs)


def _build_fireworks_vision_chat_model(vision_config: Dict[str, Any]) -> Any:
    from langchain_openai import ChatOpenAI

    api_key = (os.environ.get(ENV_FIREWORKS_API_KEY) or "").strip()
    if not api_key:
        raise ValueError("FIREWORKS_API_KEY is required for architecture vision preflight")

    base_url = (
        os.environ.get(ENV_FIREWORKS_BASE_URL, "") or ""
    ).strip() or FIREWORKS_BASE_URL_DEFAULT

    model_id = vision_config["id"]
    max_tokens = int(vision_config.get("max_tokens") or 100000)

    return ChatOpenAI(
        model=model_id,
        max_tokens=max_tokens,
        temperature=0,
        api_key=api_key,
        base_url=base_url,
    )


def describe_architecture_image(
    image_b64: str,
    image_type: Optional[str],
    vision_config: Dict[str, Any],
    callbacks: Optional[List[Any]] = None,
) -> str:
    """Call the configured VL model once; return plain-text description."""
    mime = _mime_from_image_type(image_type)
    provider = (os.environ.get(ENV_MODEL_PROVIDER) or "").strip().lower()
    if provider == MODEL_PROVIDER_FIREWORKS:
        llm = _build_fireworks_vision_chat_model(vision_config)
    else:
        llm = _build_vision_chat_model(vision_config)
    msg = HumanMessage(
        content=[
            {"type": "text", "text": _VISION_PROMPT},
            {
                "type": "image_url",
                "image_url": {"url": f"data:{mime};base64,{image_b64}"},
            },
        ]
    )
    cfg = {"callbacks": callbacks} if callbacks else None
    resp = llm.invoke([msg], cfg) if cfg else llm.invoke([msg])
    text = resp.content
    if isinstance(text, list):
        parts = []
        for block in text:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        text = "\n".join(parts)
    return (text or "").strip()


def apply_architecture_vision_preflight(
    state: Dict[str, Any],
    job_id: str,
    callbacks: Optional[List[Any]] = None,
) -> None:
    """
    Mutate state in place: run VL on diagram(s), set architecture_diagram_text
    (and previous_architecture_diagram_text for version flows).
    """
    if _image_inputs_enabled():
        logger.info(
            "Architecture vision preflight skipped (THREAT_DESIGNER_ENABLE_IMAGE_INPUTS is enabled)",
            job_id=job_id,
        )
        return

    if _vision_disabled():
        return
    _prov = (os.environ.get(ENV_MODEL_PROVIDER) or "").strip().lower()
    if _prov not in (MODEL_PROVIDER_OPENROUTER, MODEL_PROVIDER_FIREWORKS):
        return

    from model_utils import _load_model_configs

    try:
        configs = _load_model_configs()
    except Exception as e:
        logger.warning("Could not load model configs for vision preflight", error=str(e))
        return

    vision = configs.architecture_vision_model
    if not vision or not vision.get("id"):
        return

    try:
        if state.get("version"):
            prev_b64 = state.get("previous_image_data")
            if prev_b64:
                logger.info(
                    "Architecture vision preflight (previous diagram)",
                    job_id=job_id,
                    model_id=vision["id"],
                )
                state["previous_architecture_diagram_text"] = describe_architecture_image(
                    prev_b64,
                    state.get("image_type"),
                    vision,
                    callbacks=callbacks,
                )
            new_b64 = state.get("image_data")
            if new_b64:
                logger.info(
                    "Architecture vision preflight (new diagram)",
                    job_id=job_id,
                    model_id=vision["id"],
                )
                state["architecture_diagram_text"] = describe_architecture_image(
                    new_b64,
                    state.get("image_type"),
                    vision,
                    callbacks=callbacks,
                )
        else:
            img = state.get("image_data")
            if not img:
                return
            logger.info(
                "Architecture vision preflight",
                job_id=job_id,
                model_id=vision["id"],
            )
            state["architecture_diagram_text"] = describe_architecture_image(
                img,
                state.get("image_type"),
                vision,
                callbacks=callbacks,
            )
    except Exception as e:
        logger.warning(
            "Architecture vision preflight failed; falling back to raw image in messages",
            job_id=job_id,
            error=str(e),
        )
        return

    try:
        _write_preflight_text_output(state, job_id, vision["id"])
    except Exception as e:
        logger.warning(
            "Architecture vision preflight text output failed",
            job_id=job_id,
            error=str(e),
        )

    # Drop base64 only when every diagram has a text replacement (avoids breaking
    # version diff when only one side was described).
    if state.get("version"):
        if state.get("previous_architecture_diagram_text") and state.get(
            "architecture_diagram_text"
        ):
            state["image_data"] = None
            state["previous_image_data"] = None
    elif state.get("architecture_diagram_text"):
        state["image_data"] = None
