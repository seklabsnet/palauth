ALTER TABLE verification_tokens DROP CONSTRAINT verification_tokens_type_check;
ALTER TABLE verification_tokens ADD CONSTRAINT verification_tokens_type_check
    CHECK (type IN ('email_verify', 'email_verify_otp', 'password_reset', 'magic_link'));
