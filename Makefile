FLAGS=-ldflags -w -trimpath

run::
	go run ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=mockery.yaml --all

lint::
	golangci-lint run ./...

devguard::
	go build $(FLAGS) -o devguard ./cmd/devguard/main.go

devguard-cli::
	go build $(FLAGS) -o devguard-cli cmd/devguard-cli/main.go

devguard-scanner::
	go build $(FLAGS) -o devguard-scanner cmd/devguard-scanner/main.go