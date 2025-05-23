FLAGS=-ldflags -w -trimpath

run::
	go run ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	# golangci-lint run ./... # golangci-lint 1.X is currently not compatible with Golang 1.24
	docker run --rm -v ./:/app:ro -w /app golangci/golangci-lint:v2.1.6 golangci-lint run

lint-fix::
	docker run --rm -v ./:/app:rw -w /app golangci/golangci-lint:v2.1.6 golangci-lint run --fix

test::
	go list ./... | grep -v "/mocks" | xargs go test "$1"

devguard::
	go build $(FLAGS) -o devguard ./cmd/devguard/main.go

devguard-cli::
	go build $(FLAGS) -o devguard-cli cmd/devguard-cli/main.go

devguard-scanner::
	go build $(FLAGS) -o devguard-scanner cmd/devguard-scanner/main.go