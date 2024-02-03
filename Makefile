run::
	go run ./cmd/flawfix/main.go


clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	golangci-lint run ./...

cli::
	go build -o flawfix-cli ./cmd/flawfix-cli/main.go

run-cli::
	go run ./cmd/flawfix-cli/main.go