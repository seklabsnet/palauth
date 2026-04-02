-- Track failed verification attempts for OTP brute-force protection (PSD2 RTS Art. 4(3)(d)).
ALTER TABLE verification_tokens ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
