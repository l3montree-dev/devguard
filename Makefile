FLAGS=-ldflags -w -trimpath -tags netgo,osusergo -buildmode=pie

run::
	go run ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	golangci-lint run ./...

app::
	go build $(FLAGS) -o devguard ./cmd/devguard/main.go

cli::
	go build $(FLAGS) -o devguard-cli cmd/devguard-cli/main.go

scanner::
	go build $(FLAGS) -o devguard-scanner cmd/devguard-scanner/main.go