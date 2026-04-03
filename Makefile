.PHONY: build test lint migrate migrate-down sqlc dev dev-down clean openapi-validate

BINARY := palauth
BUILD_DIR := bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/server

test:
	go test ./... -race -count=1

lint:
	golangci-lint run ./...

migrate:
	goose -dir migrations postgres "$$PALAUTH_DATABASE_URL" up

migrate-down:
	goose -dir migrations postgres "$$PALAUTH_DATABASE_URL" down

sqlc:
	sqlc generate

dev:
	docker compose -f docker/docker-compose.yml up -d
	air -c .air.toml

dev-down:
	docker compose -f docker/docker-compose.yml down

openapi-validate:
	npx --yes @redocly/cli lint api/openapi.yaml --skip-rule no-unused-components

clean:
	rm -rf $(BUILD_DIR)
