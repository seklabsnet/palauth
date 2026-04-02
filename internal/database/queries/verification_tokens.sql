-- name: CreateVerificationToken :one
INSERT INTO verification_tokens (id, project_id, user_id, token_hash, type, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetVerificationTokenByHash :one
SELECT * FROM verification_tokens WHERE token_hash = $1 AND project_id = $2 AND used = false;

-- name: GetVerificationTokenByUserAndType :one
SELECT * FROM verification_tokens
WHERE user_id = $1 AND type = $2 AND project_id = $3 AND used = false
ORDER BY created_at DESC LIMIT 1;

-- name: InvalidateVerificationTokens :exec
UPDATE verification_tokens SET used = true
WHERE user_id = $1 AND type = $2 AND project_id = $3 AND used = false;

-- name: MarkVerificationTokenUsed :exec
UPDATE verification_tokens SET used = true WHERE id = $1 AND project_id = $2;

-- name: IncrementVerificationFailedAttempts :one
UPDATE verification_tokens SET failed_attempts = failed_attempts + 1
WHERE id = $1
RETURNING failed_attempts;
