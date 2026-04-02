-- name: CreateUser :one
INSERT INTO users (id, project_id, email_encrypted, email_hash, password_hash, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 AND project_id = $2;

-- name: GetUserByEmailHash :one
SELECT * FROM users WHERE project_id = $1 AND email_hash = $2;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2, updated_at = now()
WHERE id = $1 AND project_id = $3;

-- name: UpdateUserEmailVerified :exec
UPDATE users SET email_verified = true, updated_at = now()
WHERE id = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login_at = now(), updated_at = now()
WHERE id = $1 AND project_id = $2;

-- name: BanUser :exec
UPDATE users SET banned = true, ban_reason = $2, updated_at = now()
WHERE id = $1;

-- name: UnbanUser :exec
UPDATE users SET banned = false, ban_reason = NULL, updated_at = now()
WHERE id = $1;

-- name: ListUsersByProject :many
SELECT * FROM users WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountUsersByProject :one
SELECT count(*) FROM users WHERE project_id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: GetInactiveUsers :many
SELECT id, project_id FROM users
WHERE last_login_at < now() - make_interval(days => $1::int)
AND banned = false;
