-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS has_mfa;
