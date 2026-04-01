-- name: CreateAdminUser :one
INSERT INTO admin_users (id, email, password_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetAdminByEmail :one
SELECT * FROM admin_users WHERE email = $1;

-- name: GetAdminByID :one
SELECT * FROM admin_users WHERE id = $1;

-- name: ListAdmins :many
SELECT id, email, role, created_at FROM admin_users ORDER BY created_at DESC;

-- name: DeleteAdmin :exec
DELETE FROM admin_users WHERE id = $1;

-- name: CountAdmins :one
SELECT count(*) FROM admin_users;
