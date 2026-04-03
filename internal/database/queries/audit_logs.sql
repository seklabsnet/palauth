-- name: CreateAuditLog :one
INSERT INTO audit_logs (id, project_id, trace_id, event_type, actor_encrypted, target_type, target_id, result, auth_method, risk_score, metadata_encrypted, prev_hash, event_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetLastAuditLog :one
SELECT * FROM audit_logs WHERE project_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: ListAuditLogsAsc :many
-- NOTE: No LIMIT — used by Verify() and Export() which need full chain.
-- Acceptable for Phase 0 (bounded project sizes). Add streaming/batching for production scale.
SELECT * FROM audit_logs WHERE project_id = $1 ORDER BY created_at ASC, id ASC;

-- name: ListAuditLogsCursor :many
SELECT * FROM audit_logs
WHERE project_id = @project_id
  AND (created_at < @cursor_created_at OR (created_at = @cursor_created_at AND id < @cursor_id))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListAuditLogsCursorByType :many
SELECT * FROM audit_logs
WHERE project_id = @project_id AND event_type = @event_type
  AND (created_at < @cursor_created_at OR (created_at = @cursor_created_at AND id < @cursor_id))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListAuditLogsFirst :many
SELECT * FROM audit_logs
WHERE project_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: ListAuditLogsFirstByType :many
SELECT * FROM audit_logs
WHERE project_id = $1 AND event_type = $2
ORDER BY created_at DESC, id DESC
LIMIT $3;

-- name: CountAuditLogs :one
SELECT count(*) FROM audit_logs WHERE project_id = $1;

-- name: CountAuditLogsByType :one
SELECT count(*) FROM audit_logs WHERE project_id = $1 AND event_type = $2;

-- name: CountRecentAuditLogsByType :one
SELECT count(*) FROM audit_logs
WHERE project_id = $1 AND event_type = $2
  AND created_at > now() - make_interval(hours => $3::int);
