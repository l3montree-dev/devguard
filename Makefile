# Use GitHub Actions environment variables if available, otherwise use git commands
GIT_DESCRIBE ?= $(or $(GITHUB_REF_NAME),$(shell git describe --tags --dirty --always))
GIT_COMMIT ?= $(or $(GITHUB_SHA),$(shell git rev-parse HEAD))
GIT_BRANCH ?= $(or $(GITHUB_REF_NAME),$(shell git rev-parse --abbrev-ref HEAD))
DATE ?= $(shell date +%Y-%m-%dT%H:%M:%S%z)
VERSION_FLAGS=-ldflags="-X github.com/l3montree-dev/devguard/config.Version=$(GIT_DESCRIBE) \
                        -X github.com/l3montree-dev/devguard/config.Commit=$(GIT_COMMIT) \
                        -X github.com/l3montree-dev/devguard/config.Branch=$(GIT_BRANCH) \
                        -X github.com/l3montree-dev/devguard/config.BuildDate=$(DATE)"
FLAGS=$(VERSION_FLAGS) -trimpath

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

docs::
	swag init -g cmd/devguard/main.go -o docs --v3.1
	@rm -f docs/docs.go
	@echo "OpenAPI spec generated at docs/swagger.json and docs/swagger.yaml"

cli-docs::
	@echo "Generating CLI documentation..."
	@go run cmd/doc-gen/main.go
	@echo "CLI documentation generated in docs/scanner/"

NIX_CACHE_BUCKET     ?= nix.garage.l3montree.cloud
NIX_CACHE_ENDPOINT   ?= s3.garage.l3montree.cloud
NIX_CACHE_REGION     ?= garage
NIX_CACHE_SECRET_KEY ?= /etc/nix/cache-priv-key.pem

nix-cache-push::
	@echo "Building dependency bundles..."
	nix build --no-link .#deps
	nix build --no-link .#packages.x86_64-linux.deps
	@echo "Pushing closures to S3 cache..."
	nix copy \
		$$(nix path-info -r .#deps) \
		$$(nix path-info -r .#packages.x86_64-linux.deps) \
		--to 's3://$(NIX_CACHE_BUCKET)?endpoint=$(NIX_CACHE_ENDPOINT)&region=$(NIX_CACHE_REGION)&scheme=https&profile=garage&secret-key=$(NIX_CACHE_SECRET_KEY)'