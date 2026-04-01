-- name: CreateSession :one
INSERT INTO sessions (id, project_id, user_id, ip, user_agent, device_fp_hash, acr, amr, idle_timeout_at, abs_timeout_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions WHERE id = $1 AND revoked_at IS NULL;

-- name: UpdateSessionActivity :exec
UPDATE sessions SET last_activity = now(), idle_timeout_at = $2
WHERE id = $1;

-- name: RevokeSession :exec
UPDATE sessions SET revoked_at = now() WHERE id = $1;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: ListActiveSessions :many
SELECT * FROM sessions
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;
