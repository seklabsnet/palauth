ALTER TABLE refresh_tokens ADD COLUMN project_id TEXT NOT NULL DEFAULT '' REFERENCES projects(id);
ALTER TABLE refresh_tokens ALTER COLUMN project_id DROP DEFAULT;
CREATE INDEX idx_rt_project ON refresh_tokens(project_id);
