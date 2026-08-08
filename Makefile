.PHONY: generate build test lint web docker

generate:
	pnpm generate

build:
	go build ./cmd/platform93

test:
	go test ./...
	pnpm -r test

lint:
	go vet ./...
	pnpm -r lint

web:
	pnpm --filter @platform93/admin build

docker:
	docker build -t platform93:dev .
