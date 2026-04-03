-- +goose Up
ALTER TABLE users ADD COLUMN has_mfa BOOLEAN NOT NULL DEFAULT false;
