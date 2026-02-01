APP_NAME=pif

.PHONY: setup dev test lint typecheck build check release

setup:
	go mod download

dev:
	go run ./cmd/$(APP_NAME) -config config.yaml

test:
	go test ./...

lint:
	go vet ./...

typecheck:
	go test ./... -run TestNonExistent -count=0

build:
	go build ./cmd/$(APP_NAME)

check: lint typecheck test build

release:
	mkdir -p dist
	go build -o dist/$(APP_NAME) ./cmd/$(APP_NAME)
