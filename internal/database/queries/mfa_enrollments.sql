-- name: CreateMFAEnrollment :one
INSERT INTO mfa_enrollments (id, project_id, user_id, type, secret_encrypted, verified)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetMFAEnrollment :one
SELECT * FROM mfa_enrollments WHERE id = $1 AND project_id = $2;

-- name: GetMFAEnrollmentByUserAndType :one
SELECT * FROM mfa_enrollments
WHERE user_id = $1 AND project_id = $2 AND type = $3;

-- name: GetVerifiedMFAEnrollmentByUserAndType :one
SELECT * FROM mfa_enrollments
WHERE user_id = $1 AND project_id = $2 AND type = $3 AND verified = true;

-- name: ListVerifiedMFAEnrollments :many
SELECT * FROM mfa_enrollments
WHERE user_id = $1 AND project_id = $2 AND verified = true
ORDER BY created_at ASC;

-- name: ListMFAEnrollments :many
SELECT * FROM mfa_enrollments
WHERE user_id = $1 AND project_id = $2
ORDER BY created_at ASC;

-- name: VerifyMFAEnrollment :exec
UPDATE mfa_enrollments SET verified = true
WHERE id = $1 AND project_id = $2;

-- name: DeleteMFAEnrollment :exec
DELETE FROM mfa_enrollments WHERE id = $1 AND project_id = $2;

-- name: DeleteMFAEnrollmentsByUser :exec
DELETE FROM mfa_enrollments WHERE user_id = $1 AND project_id = $2;

-- name: UpdateUserHasMFA :exec
UPDATE users SET has_mfa = $2, updated_at = now()
WHERE id = $1 AND project_id = $3;
