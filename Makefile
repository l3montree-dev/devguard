run::
	go run ./cmd/devguard/main.go

clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml

lint::
	golangci-lint run ./...

flawfind::
	docker build -t flawfind -f Dockerfile.flawfind .

hydra-client: 
	ocker compose exec hydra hydra create oauth2-client --name "DevGuard Local" --grant-type client_credentials --token-endpoint-auth-method client_secret_basic --endpoint http://127.0.0.1:4445/ --scope "devguard-m2m" --audience "devguard-m2m"