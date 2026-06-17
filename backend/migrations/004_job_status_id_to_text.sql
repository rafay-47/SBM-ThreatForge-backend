-- Migration: Update job_status for attack tree service
-- 1. Change id from UUID to TEXT (composite IDs like {uuid}_{threat_name})
-- 2. Add columns used by attack_tree_service.py

ALTER TABLE job_status ALTER COLUMN id TYPE TEXT;

ALTER TABLE job_status ADD COLUMN IF NOT EXISTS threat_model_id UUID;
ALTER TABLE job_status ADD COLUMN IF NOT EXISTS threat_name TEXT;
ALTER TABLE job_status ADD COLUMN IF NOT EXISTS error TEXT;
