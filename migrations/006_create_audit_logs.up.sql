-- Not: project_id FK YOK — bilerek. Append-only tablo, FK constraint insert performansini dusurur.
-- Ayrica GDPR erasure'da project silinse bile loglar kalir.
CREATE TABLE audit_logs (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    trace_id            TEXT,
    event_type          TEXT NOT NULL,
    actor_encrypted     BYTEA,
    target_type         TEXT,
    target_id           TEXT,
    result              TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    auth_method         TEXT,
    risk_score          REAL DEFAULT 0.0,
    metadata_encrypted  BYTEA,
    prev_hash           TEXT,
    event_hash          TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_project_time ON audit_logs(project_id, created_at DESC);
CREATE INDEX idx_audit_type_time ON audit_logs(event_type, created_at DESC);
