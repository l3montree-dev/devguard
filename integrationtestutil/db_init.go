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

	// Run embedded migrations to ensure the DB schema matches the project's
	// migration files. This creates the tables and constraints consistently
	// for integration tests.
	if err := database.RunMigrationsWithDB(db); err != nil {
		log.Printf("failed to run migrations: %s", err)
		panic(err)
	}

	return db, terminate
}

// InitSQLDatabaseContainer initializes a test database container and returns the underlying SQL DB
// and connection string instead of GORM DB. Useful for components that need direct SQL access.
func InitSQLDatabaseContainer(initDBSQLPath string) (string, string, string, string, string, func()) {
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

	return dbUser, dbPassword, host, port.Port(), dbName, terminate
}
