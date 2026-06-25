-- Migration: Rename agent_trail gaps column to gap
ALTER TABLE agent_trail RENAME COLUMN IF EXISTS gaps TO gap;
