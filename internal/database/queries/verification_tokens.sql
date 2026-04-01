-- name: CreateVerificationToken :one
INSERT INTO verification_tokens (id, project_id, user_id, token_hash, type, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetVerificationTokenByHash :one
SELECT * FROM verification_tokens WHERE token_hash = $1 AND used = false;

-- name: MarkVerificationTokenUsed :exec
UPDATE verification_tokens SET used = true WHERE id = $1;
