-- Upgrade space_document_chunks.embedding from vector(1536) to vector(2048)
-- for OpenRouter / NVIDIA Llama Nemotron Embed VL (2048 dims).
-- Run after 002 if you already applied 002 with 1536. Re-ingest space documents after this.

TRUNCATE TABLE space_document_chunks;

ALTER TABLE space_document_chunks DROP COLUMN embedding;

ALTER TABLE space_document_chunks
    ADD COLUMN embedding vector(2048) NOT NULL;

-- Drop legacy embedding ANN index if you had one from an older 002 (1536 + HNSW).
DROP INDEX IF EXISTS idx_space_document_chunks_embedding;

-- Intentionally no HNSW/IVFFlat on embedding: 2048 dims exceed pgvector’s ~2000-dim
-- index limit on standard builds. See comment in 002_pgvector_space_chunks.sql.
