-- name: CreateConsent :one
INSERT INTO user_consents (id, user_id, project_id, purpose, granted, version, ip, user_agent, granted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetUserConsents :many
SELECT * FROM user_consents WHERE user_id = $1 ORDER BY created_at DESC;

-- name: RevokeConsent :exec
UPDATE user_consents SET revoked_at = now() WHERE id = $1;
