-- Revert: set existing NULLs to abs_timeout_at, then restore NOT NULL.
UPDATE sessions SET idle_timeout_at = abs_timeout_at WHERE idle_timeout_at IS NULL;
ALTER TABLE sessions ALTER COLUMN idle_timeout_at SET NOT NULL;
