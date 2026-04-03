-- name: CreateRecoveryCode :one
INSERT INTO recovery_codes (id, user_id, project_id, code_hash)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListUnusedRecoveryCodes :many
SELECT * FROM recovery_codes
WHERE user_id = $1 AND project_id = $2 AND used = false
ORDER BY created_at ASC;

-- name: MarkRecoveryCodeUsed :exec
UPDATE recovery_codes SET used = true, used_at = now()
WHERE id = $1 AND project_id = $2;

-- name: DeleteRecoveryCodesByUser :exec
DELETE FROM recovery_codes WHERE user_id = $1 AND project_id = $2;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM recovery_codes
WHERE user_id = $1 AND project_id = $2 AND used = false;
