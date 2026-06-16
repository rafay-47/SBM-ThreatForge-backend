"""Pgvector-backed space knowledge: ingest uploaded documents and similarity search.

Embeddings default to OpenRouter (NVIDIA Llama Nemotron Embed VL, 2048-d).
Set EMBEDDING_PROVIDER=openai and OPENAI_API_KEY to use OpenAI embeddings instead.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple, Union

from utils.env_defaults import get_env
from utils.powertools_compat import Logger

LOG = Logger(serialize_stacktrace=False)

_DEFAULT_OPENROUTER_MODEL = "nvidia/llama-nemotron-embed-vl-1b-v2:free"
_DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
_DEFAULT_OPENAI_MODEL = "text-embedding-3-small"
_DIM_OPENROUTER = 2048
_DIM_OPENAI_SMALL = 1536


def _database_url() -> str:
    return (get_env("DATABASE_URL", "") or "").strip()


def _pgvector_disabled() -> bool:
    return get_env("SPACE_PGVECTOR", "true").lower() in ("0", "false", "no", "off")


def _use_openrouter() -> bool:
    """OpenRouter when EMBEDDING_PROVIDER=openrouter, or when OPENROUTER_API_KEY is set (and not forced to openai)."""
    explicit = (get_env("EMBEDDING_PROVIDER", "") or "").strip().lower()
    if explicit == "openrouter":
        return True
    if explicit == "openai":
        return False
    return bool(get_env("OPENROUTER_API_KEY", "").strip())


def _api_key_for_embeddings() -> str:
    if _use_openrouter():
        k = (get_env("OPENROUTER_API_KEY", "") or "").strip()
        if k:
            return k
    return (get_env("OPENAI_API_KEY", "") or "").strip()


def is_pgvector_configured() -> bool:
    """True when DATABASE_URL and an embedding API key (OpenRouter or OpenAI) are set."""
    if _pgvector_disabled():
        return False
    return bool(_database_url() and _api_key_for_embeddings())


def embedding_model_id() -> str:
    if _use_openrouter():
        return (
            get_env("EMBEDDING_MODEL", "")
            or get_env("OPENAI_EMBEDDING_MODEL", "")
            or _DEFAULT_OPENROUTER_MODEL
        )
    return get_env("OPENAI_EMBEDDING_MODEL", _DEFAULT_OPENAI_MODEL) or _DEFAULT_OPENAI_MODEL


def embedding_dimensions() -> int:
    raw = (get_env("EMBEDDING_DIMENSIONS", "") or "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _DIM_OPENROUTER if _use_openrouter() else _DIM_OPENAI_SMALL


def _openrouter_extra_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    referer = (get_env("OPENROUTER_HTTP_REFERER", "") or "").strip()
    title = (get_env("OPENROUTER_SITE_TITLE", "") or "").strip()
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-OpenRouter-Title"] = title
    return headers


def _embedding_client():
    from openai import OpenAI

    key = _api_key_for_embeddings()
    if _use_openrouter():
        base = (get_env("OPENROUTER_BASE_URL", "") or "").strip() or _DEFAULT_OPENROUTER_BASE
        return OpenAI(base_url=base, api_key=key)
    return OpenAI(api_key=key)


def _embeddings_create_kwargs(
    model: str,
    input_payload: Union[str, List[str], List[Dict[str, Any]]],
) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "model": model,
        "input": input_payload,
        "encoding_format": "float",
    }
    if _use_openrouter():
        extra = _openrouter_extra_headers()
        if extra:
            kwargs["extra_headers"] = extra
    return kwargs


def _embed_batch(texts: Sequence[str]) -> List[List[float]]:
    """Call OpenAI-compatible embeddings API (OpenRouter or OpenAI)."""
    if not texts:
        return []

    model = embedding_model_id()
    client = _embedding_client()

    # OpenRouter docs: simple string or list of strings works for text embeddings.
    out: List[List[float]] = []
    batch_size = 16
    for i in range(0, len(texts), batch_size):
        batch = list(texts[i : i + batch_size])
        kwargs = _embeddings_create_kwargs(model, batch)
        resp = client.embeddings.create(**kwargs)
        by_idx = {item.index: item.embedding for item in resp.data}
        for j in range(len(batch)):
            out.append(by_idx[j])
    return out


def _chunk_text(text: str, max_chars: int = 1200, overlap: int = 200) -> List[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


def extract_text_from_file(filename: str, data: bytes) -> str:
    """Best-effort text extraction for common space uploads."""
    lower = filename.lower()
    if lower.endswith((".txt", ".md", ".csv", ".json")):
        return data.decode("utf-8", errors="replace")

    if lower.endswith(".pdf"):
        try:
            from io import BytesIO

            from pypdf import PdfReader

            reader = PdfReader(BytesIO(data))
            parts: List[str] = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    parts.append(t)
            return "\n\n".join(parts)
        except Exception as e:
            LOG.warning("PDF text extraction failed", error=str(e), filename=filename)
            return ""

    LOG.warning("Unsupported file type for pgvector ingest", filename=filename)
    return ""


def _vector_literal(values: Sequence[float]) -> str:
    return "[" + ",".join(f"{v:.8f}" for v in values) + "]"


def _get_conn():
    import psycopg2

    return psycopg2.connect(_database_url())


def delete_chunks_for_document(space_id: str, document_id: str) -> None:
    if not is_pgvector_configured():
        return
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM space_document_chunks WHERE space_id = %s AND document_id = %s",
                (space_id, document_id),
            )
        conn.commit()
    finally:
        conn.close()


def ingest_space_document(
    *,
    space_id: str,
    document_id: str,
    filename: str,
    file_bytes: bytes,
    uploaded_by: str = "",
) -> Tuple[bool, str]:
    """
    Chunk, embed, and store rows in space_document_chunks.
    Returns (success, message).
    """
    if not is_pgvector_configured():
        return False, "Pgvector not configured"

    text = extract_text_from_file(filename, file_bytes)
    if not text or not text.strip():
        return False, "No extractable text from document"

    chunks = _chunk_text(text)
    if not chunks:
        return False, "No chunks produced"

    try:
        embeddings = _embed_batch(chunks)
    except Exception as e:
        LOG.warning("Embedding failed", error=str(e), document_id=document_id)
        return False, f"Embedding failed: {e}"

    dims = embedding_dimensions()
    for emb in embeddings:
        if len(emb) != dims:
            return False, (
                f"Embedding dimension {len(emb)} != expected {dims} "
                f"(set EMBEDDING_DIMENSIONS to match the model)"
            )

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM space_document_chunks WHERE space_id = %s AND document_id = %s",
                (space_id, document_id),
            )
            for idx, (chunk, emb) in enumerate(zip(chunks, embeddings)):
                cur.execute(
                    """
                    INSERT INTO space_document_chunks
                        (space_id, document_id, chunk_index, content, embedding)
                    VALUES (%s, %s, %s, %s, %s::vector)
                    """,
                    (
                        space_id,
                        document_id,
                        idx,
                        chunk,
                        _vector_literal(emb),
                    ),
                )
        conn.commit()
    except Exception as e:
        conn.rollback()
        LOG.warning("Pgvector ingest failed", error=str(e), document_id=document_id)
        return False, f"Ingest failed: {e}"
    finally:
        conn.close()

    LOG.info(
        "Pgvector ingest complete",
        space_id=space_id,
        document_id=document_id,
        chunks=len(chunks),
        uploaded_by=uploaded_by or None,
    )
    return True, f"Ingested {len(chunks)} chunks"


def search_space_knowledge_base(
    query: str,
    space_id: str,
    max_results: int = 5,
) -> str:
    """
    Return formatted retrieval text (same shape as Bedrock KB tool output).
    """
    if not is_pgvector_configured():
        return (
            "Knowledge base not configured for pgvector "
            "(set DATABASE_URL and OPENROUTER_API_KEY or OPENAI_API_KEY)."
        )

    q = (query or "").strip()
    if not q:
        return "Empty query."

    try:
        q_emb = _embed_batch([q])[0]
    except Exception as e:
        LOG.warning("Query embedding failed", error=str(e))
        return f"Knowledge base query failed: {e}"

    dims = embedding_dimensions()
    if len(q_emb) != dims:
        return (
            f"Knowledge base query failed: query embedding dim {len(q_emb)} "
            f"!= expected {dims}"
        )

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT content, 1 - (embedding <=> %s::vector) AS score
                FROM space_document_chunks
                WHERE space_id = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (_vector_literal(q_emb), space_id, _vector_literal(q_emb), max_results),
            )
            rows = cur.fetchall()
    except Exception as e:
        LOG.warning("Pgvector search failed", error=str(e))
        return f"Knowledge base query failed: {e}"
    finally:
        conn.close()

    if not rows:
        return "No relevant results found for this query."

    parts: List[str] = []
    for i, (content, score) in enumerate(rows, 1):
        if content:
            try:
                sc = float(score)
            except (TypeError, ValueError):
                sc = 0.0
            parts.append(f"[Result {i} | relevance={sc:.2f}]\n{str(content).strip()}")

    return "\n\n---\n\n".join(parts) if parts else "No relevant results found."
