-- name: CreatePasswordHistory :exec
INSERT INTO password_history (id, user_id, hash) VALUES ($1, $2, $3);

-- name: GetRecentPasswords :many
SELECT hash FROM password_history
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;
