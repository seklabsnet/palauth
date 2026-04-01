.PHONY: build test lint migrate dev dev-down clean

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

dev:
	docker compose -f docker/docker-compose.yml up -d
	air -c .air.toml

dev-down:
	docker compose -f docker/docker-compose.yml down

clean:
	rm -rf $(BUILD_DIR)
