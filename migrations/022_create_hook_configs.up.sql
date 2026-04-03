CREATE TABLE hook_configs (
  id                    TEXT PRIMARY KEY NOT NULL,
  project_id            TEXT NOT NULL REFERENCES projects(id),
  event                 TEXT NOT NULL,
  url                   TEXT NOT NULL,
  signing_key_encrypted BYTEA NOT NULL,
  timeout_ms            INTEGER NOT NULL DEFAULT 15000,
  failure_mode          TEXT NOT NULL DEFAULT 'deny' CHECK (failure_mode IN ('deny', 'allow')),
  enabled               BOOLEAN NOT NULL DEFAULT true,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_hook_project_event ON hook_configs(project_id, event) WHERE enabled = true;
