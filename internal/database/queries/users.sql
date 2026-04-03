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
WHERE id = $1 AND project_id = $3;

-- name: UnbanUser :exec
UPDATE users SET banned = false, ban_reason = NULL, updated_at = now()
WHERE id = $1 AND project_id = $2;

-- name: ListUsersByProject :many
SELECT * FROM users WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;

-- name: CountUsersByProject :one
SELECT count(*) FROM users WHERE project_id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1 AND project_id = $2;

-- name: GetInactiveUsers :many
SELECT id, project_id FROM users
WHERE (last_login_at < now() - make_interval(days => $1::int)
       OR (last_login_at IS NULL AND created_at < now() - make_interval(days => $1::int)))
AND banned = false;

-- name: ListUsersCursor :many
SELECT * FROM users
WHERE project_id = @project_id
  AND (created_at < @cursor_created_at OR (created_at = @cursor_created_at AND id < @cursor_id))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListUsersCursorBanned :many
SELECT * FROM users
WHERE project_id = @project_id
  AND banned = @banned
  AND (created_at < @cursor_created_at OR (created_at = @cursor_created_at AND id < @cursor_id))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListUsersFirst :many
SELECT * FROM users
WHERE project_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: ListUsersFirstBanned :many
SELECT * FROM users
WHERE project_id = $1 AND banned = $2
ORDER BY created_at DESC, id DESC
LIMIT $3;

-- name: ListUsersByEmailHash :many
SELECT * FROM users
WHERE project_id = $1 AND email_hash = $2
ORDER BY created_at DESC, id DESC
LIMIT $3;

-- name: CountActiveUsersByProject :one
SELECT count(*) FROM users
WHERE project_id = $1
  AND last_login_at > now() - interval '30 days';

-- name: UpdateUserMetadata :exec
UPDATE users SET metadata = $2, updated_at = now()
WHERE id = $1 AND project_id = $3;

-- name: UpdateUserEmailAndMetadata :exec
UPDATE users SET
  email_verified = $2,
  metadata = $3,
  updated_at = now()
WHERE id = $1 AND project_id = $4;

-- name: DeleteUserEncryptionKeys :exec
DELETE FROM encryption_keys WHERE user_id = $1 AND project_id = $2;

-- name: DeleteUserPasswordHistory :exec
DELETE FROM password_history WHERE user_id = $1;

-- name: DeleteUserVerificationTokens :exec
DELETE FROM verification_tokens WHERE user_id = $1 AND project_id = $2;

-- name: DeleteUserConsents :exec
DELETE FROM user_consents WHERE user_id = $1 AND project_id = $2;

-- name: DeleteUserRefreshTokens :exec
DELETE FROM refresh_tokens WHERE user_id = $1 AND project_id = $2;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1 AND project_id = $2;
