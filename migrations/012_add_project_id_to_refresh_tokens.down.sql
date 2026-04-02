DROP INDEX IF EXISTS idx_rt_project;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS project_id;
