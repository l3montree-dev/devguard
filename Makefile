run::
	go run ./cmd/flawfix/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	golangci-lint run ./...

flawfind::
	docker build -t flawfind -f Dockerfile.flawfind .