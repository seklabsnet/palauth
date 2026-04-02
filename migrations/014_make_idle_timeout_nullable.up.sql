-- AAL1 sessions have no idle timeout per NIST 800-63B-4.
-- Make idle_timeout_at nullable to support this.
ALTER TABLE sessions ALTER COLUMN idle_timeout_at DROP NOT NULL;
