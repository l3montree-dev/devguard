run::
	go run ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	golangci-lint run ./...