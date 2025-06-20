package integrationtestutil

import (
	"context"
	"log"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func InitDatabaseContainer(initDBSQLPath string) (core.DB, func()) {
	ctx := context.Background()

	dbName := "devguard"
	dbUser := "user"
	dbPassword := "password"

	postgresC, err := postgres.Run(ctx,
		"ghcr.io/l3montree-dev/devguard-postgresql:v0.4.16",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.WithInitScripts(initDBSQLPath),
		postgres.BasicWaitStrategies(),
	)

	terminate := func() {
		if err := testcontainers.TerminateContainer(postgresC); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}
	if err != nil {
		slog.Info("failed to start postgres container", "error", err)
		panic(err)
	}

	host, _ := postgresC.Host(ctx)
	port, _ := postgresC.MappedPort(ctx, "5432")

	db, err := database.NewConnection(
		host, dbUser, dbPassword, dbName, port.Port(),
	)

	if err != nil {
		log.Printf("failed to connect to database: %s", err)
		panic(err)
	}

	return db, terminate
}
