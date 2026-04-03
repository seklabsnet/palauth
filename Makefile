.PHONY: build test lint migrate migrate-down sqlc dev dev-down clean openapi-validate docker-build docker-up docker-down docker-logs docker-dev docker-dev-down

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

docker-build:
	docker compose -f docker/docker-compose.prod.yml build

docker-up:
	docker compose -f docker/docker-compose.prod.yml up -d

docker-down:
	docker compose -f docker/docker-compose.prod.yml down

docker-logs:
	docker compose -f docker/docker-compose.prod.yml logs -f

docker-dev:
	docker compose -f docker/docker-compose.dev.yml up

docker-dev-down:
	docker compose -f docker/docker-compose.dev.yml down

clean:
	rm -rf $(BUILD_DIR)
