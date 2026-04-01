-- name: CreateAuditLog :one
INSERT INTO audit_logs (id, project_id, trace_id, event_type, actor_encrypted, target_type, target_id, result, auth_method, risk_score, metadata_encrypted, prev_hash, event_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetLastAuditLog :one
SELECT * FROM audit_logs WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: ListAuditLogsByType :many
SELECT * FROM audit_logs WHERE project_id = $1 AND event_type = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4;
