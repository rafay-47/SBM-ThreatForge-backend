-- Threat Designer Supabase Schema
-- Run this in Supabase Dashboard → SQL Editor
-- This creates all tables needed by the backend services

-- ============================================================================
-- Core Tables
-- ============================================================================

-- job_status: tracks agent execution state (maps to DynamoDB job_status table)
CREATE TABLE IF NOT EXISTS job_status (
    id UUID PRIMARY KEY,
    state TEXT NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry INT DEFAULT 0,
    session_id UUID,
    execution_owner TEXT,
    owner TEXT,
    detail TEXT,
    cancelled BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    parent_id UUID,
    mirror_attack_trees BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_job_status_execution_owner
    ON job_status (execution_owner, "timestamp" DESC);

-- agent_state: stores completed threat models (maps to DynamoDB agent_state table)
CREATE TABLE IF NOT EXISTS agent_state (
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
    owner TEXT NOT NULL,
    retry INT,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_modified_at TIMESTAMPTZ,
    last_modified_by TEXT,
    content_hash TEXT,
    application_type TEXT,
    token_usage JSONB,
    space_insights JSONB,
    parent_id UUID,
    space_id UUID,
    is_shared BOOLEAN DEFAULT FALSE,
    backup JSONB
);

CREATE INDEX IF NOT EXISTS idx_agent_state_owner_timestamp
    ON agent_state (owner, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_agent_state_space_id
    ON agent_state (space_id);

-- agent_trail: stores reasoning trail data
CREATE TABLE IF NOT EXISTS agent_trail (
    id UUID PRIMARY KEY,
    assets TEXT,
    flows TEXT,
    threats TEXT,
    gap TEXT,
    space_context TEXT,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- backup: stores threat model backups for replay
CREATE TABLE IF NOT EXISTS backup (
    job_id UUID PRIMARY KEY,
    data JSONB NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- sharing: threat model collaborator records
CREATE TABLE IF NOT EXISTS sharing (
    threat_model_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    access_level TEXT NOT NULL DEFAULT 'READ_ONLY',
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shared_by TEXT NOT NULL,
    PRIMARY KEY (threat_model_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_sharing_user_timestamp
    ON sharing (user_id, shared_at DESC);

-- locks: edit locks for threat models
CREATE TABLE IF NOT EXISTS locks (
    threat_model_id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT,
    token UUID NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_locks_expires
    ON locks (expires_at);

-- ============================================================================
-- Attack Tree Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS attack_trees (
    attack_tree_id UUID PRIMARY KEY,
    threat_model_id UUID NOT NULL,
    threat_name TEXT NOT NULL,
    stride_category TEXT,
    likelihood TEXT,
    attack_tree_data JSONB,
    state TEXT NOT NULL DEFAULT 'pending',
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_modified_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_trees_threat_model
    ON attack_trees (threat_model_id);
CREATE INDEX IF NOT EXISTS idx_attack_trees_state
    ON attack_trees (state);

-- ============================================================================
-- Spaces Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS spaces (
    space_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    owner TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_spaces_owner
    ON spaces (owner);

CREATE TABLE IF NOT EXISTS space_sharing (
    space_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    access_level TEXT NOT NULL DEFAULT 'READ_ONLY',
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    shared_by TEXT NOT NULL,
    PRIMARY KEY (space_id, user_id)
);

CREATE TABLE IF NOT EXISTS space_documents (
    document_id UUID PRIMARY KEY,
    space_id UUID NOT NULL,
    filename TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    content_type TEXT,
    file_size BIGINT,
    metadata JSONB,
    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT DEFAULT 'READY'
);

CREATE INDEX IF NOT EXISTS idx_space_documents_space
    ON space_documents (space_id);

-- ============================================================================
-- Sentry Session Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS sentry_sessions (
    session_header TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    created_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_sentry_sessions_session_id
    ON sentry_sessions (session_id);

-- ============================================================================
-- Enable Row Level Security (optional, for multi-tenant)
-- ============================================================================
-- Uncomment these if you want Supabase to enforce access control at DB level.

-- ALTER TABLE agent_state ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sharing ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE locks ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE spaces ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE space_sharing ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE space_documents ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE attack_trees ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE job_status ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE agent_trail ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE backup ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sentry_sessions ENABLE ROW LEVEL SECURITY;
