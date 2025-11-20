GIT_DESCRIBE=$(shell git describe --tags --dirty --always)
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
DATE=$(shell date +%Y-%m-%dT%H:%M:%S%z)
VERSION_FLAGS=-ldflags="-X github.com/l3montree-dev/devguard/config.Version=$(GIT_DESCRIBE) \
                        -X github.com/l3montree-dev/devguard/config.Commit=$(GIT_COMMIT) \
                        -X github.com/l3montree-dev/devguard/config.Branch=$(GIT_BRANCH) \
                        -X github.com/l3montree-dev/devguard/config.BuildDate=$(DATE)"
FLAGS=$(VERSION_FLAGS) -w -trimpath

run::
	go run $(VERSION_FLAGS) ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
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