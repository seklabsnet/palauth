-- +goose Down
ALTER TABLE encryption_keys DROP CONSTRAINT encryption_keys_key_type_check;
ALTER TABLE encryption_keys ADD CONSTRAINT encryption_keys_key_type_check
  CHECK (key_type IN ('project_dek', 'user_dek'));
