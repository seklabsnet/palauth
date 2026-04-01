-- name: CreateEncryptionKey :one
INSERT INTO encryption_keys (id, project_id, user_id, encrypted_key, key_type)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetProjectDEK :one
SELECT * FROM encryption_keys
WHERE project_id = $1 AND key_type = 'project_dek' AND revoked_at IS NULL;

-- name: GetUserDEK :one
SELECT * FROM encryption_keys
WHERE user_id = $1 AND key_type = 'user_dek' AND revoked_at IS NULL;

-- name: RevokeUserDEK :exec
UPDATE encryption_keys SET revoked_at = now()
WHERE user_id = $1 AND key_type = 'user_dek' AND revoked_at IS NULL;
