-- Space document chunks for pgvector RAG (replaces Bedrock KB for non-AWS deployments).
-- Requires: CREATE EXTENSION IF NOT EXISTS vector;
-- Run in Supabase SQL Editor after enabling the "vector" extension under Database → Extensions.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS space_document_chunks (
    id BIGSERIAL PRIMARY KEY,
    space_id UUID NOT NULL,
    document_id UUID NOT NULL,
    chunk_index INT NOT NULL,
    content TEXT NOT NULL,
    -- Default: OpenRouter nvidia/llama-nemotron-embed-vl-1b-v2 (2048 dims). See 003 if migrating from 1536.
    embedding vector(2048) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (space_id, document_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS idx_space_document_chunks_space_id
    ON space_document_chunks (space_id);

CREATE INDEX IF NOT EXISTS idx_space_document_chunks_document
    ON space_document_chunks (space_id, document_id);

-- No ANN index on `embedding`: pgvector HNSW/IVFFlat are limited to 2000 dimensions on
-- typical PostgreSQL page sizes, but Nemotron/OpenRouter embeddings use 2048 dims.
-- Queries filter by space_id (indexed above) then ORDER BY embedding <=> ... LIMIT n.
