-- +goose Up
ALTER TABLE admin_users ADD COLUMN has_mfa BOOLEAN NOT NULL DEFAULT false;
