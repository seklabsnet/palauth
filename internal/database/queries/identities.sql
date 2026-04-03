-- name: CreateIdentity :one
INSERT INTO identities (id, project_id, user_id, provider, provider_user_id, provider_data)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetIdentityByProviderUser :one
SELECT * FROM identities
WHERE project_id = $1 AND provider = $2 AND provider_user_id = $3;

-- name: ListIdentitiesByUser :many
SELECT * FROM identities
WHERE user_id = $1 AND project_id = $2
ORDER BY created_at DESC;

-- name: DeleteIdentity :exec
DELETE FROM identities
WHERE id = $1 AND user_id = $2 AND project_id = $3;

-- name: CountIdentitiesByUser :one
SELECT count(*) FROM identities
WHERE user_id = $1 AND project_id = $2;
