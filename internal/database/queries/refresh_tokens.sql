-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (id, project_id, session_id, user_id, token_hash, family_id, parent_id, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: GetRefreshTokenByHashForUpdate :one
SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE;

-- name: MarkRefreshTokenUsed :exec
UPDATE refresh_tokens SET used = true WHERE id = $1;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens SET used = true WHERE family_id = $1;

-- name: GetChildRefreshToken :one
SELECT * FROM refresh_tokens WHERE parent_id = $1 AND used = false ORDER BY created_at DESC LIMIT 1;

-- name: GetChildRefreshTokenForUpdate :one
SELECT * FROM refresh_tokens WHERE parent_id = $1 AND used = false ORDER BY created_at DESC LIMIT 1 FOR UPDATE;

-- name: UpdateRefreshTokenHash :exec
UPDATE refresh_tokens SET token_hash = $1 WHERE id = $2;
