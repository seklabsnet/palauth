CREATE TABLE hook_logs (
  id              TEXT PRIMARY KEY NOT NULL,
  hook_config_id  TEXT NOT NULL REFERENCES hook_configs(id),
  project_id      TEXT NOT NULL,
  event           TEXT NOT NULL,
  request_body    JSONB,
  response_body   JSONB,
  response_status INTEGER,
  latency_ms      INTEGER NOT NULL,
  result          TEXT NOT NULL CHECK (result IN ('allow', 'deny', 'timeout', 'error')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_hooklog_config ON hook_logs(hook_config_id, created_at DESC);
