-- name: CreateAPIKey :one
INSERT INTO api_keys (id, project_id, key_hash, key_prefix, key_type, name)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAPIKeyByHash :one
SELECT * FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL;

-- name: ListAPIKeys :many
SELECT * FROM api_keys WHERE project_id = $1 ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = now() WHERE id = $1;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used = now() WHERE id = $1;

-- name: GetAPIKeyByHashWithGrace :one
SELECT * FROM api_keys WHERE key_hash = $1 AND (revoked_at IS NULL OR revoked_at > now());

-- name: RevokeAPIKeyWithGrace :exec
UPDATE api_keys SET revoked_at = now() + interval '30 seconds' WHERE id = $1 AND revoked_at IS NULL;
