-- name: ListEnabledHooksByProjectEvent :many
SELECT * FROM hook_configs
WHERE project_id = $1 AND event = $2 AND enabled = true
ORDER BY created_at ASC;

-- name: ListHooksByProject :many
SELECT * FROM hook_configs
WHERE project_id = $1
ORDER BY created_at DESC;

-- name: GetHookConfig :one
SELECT * FROM hook_configs
WHERE id = $1 AND project_id = $2;

-- name: CreateHookConfig :one
INSERT INTO hook_configs (id, project_id, event, url, signing_key_encrypted, timeout_ms, failure_mode, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: UpdateHookConfig :one
UPDATE hook_configs
SET event = $3, url = $4, timeout_ms = $5, failure_mode = $6, enabled = $7
WHERE id = $1 AND project_id = $2
RETURNING *;

-- name: DeleteHookConfig :exec
DELETE FROM hook_configs WHERE id = $1 AND project_id = $2;

-- name: CreateHookLog :one
INSERT INTO hook_logs (id, hook_config_id, project_id, event, request_body, response_body, response_status, latency_ms, result)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: ListHookLogs :many
SELECT * FROM hook_logs
WHERE hook_config_id = $1 AND project_id = $2
ORDER BY created_at DESC
LIMIT $3;
