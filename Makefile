run::
	go run ./cmd/flawfix/main.go


clean::
	docker compose down -v && docker compose up -d

mocks::
	mockery --config=.mockery.yaml