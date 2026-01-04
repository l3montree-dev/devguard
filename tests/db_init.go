package tests

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func InitDatabaseContainer(initDBSQLPath string) (shared.DB, *pgxpool.Pool, func()) {
	pool, terminate := InitRawDatabaseContainer(initDBSQLPath)
	db := database.NewGormDB(pool)

	// Run embedded migrations to ensure the DB schema matches the project's
	// migration files. This creates the tables and constraints consistently
	// for integration tests.
	if err := database.RunMigrationsWithDB(db); err != nil {
		log.Printf("failed to run migrations: %s", err)
		panic(err)
	}

	return db, pool, terminate
}

func InitRawDatabaseContainer(initDBSQLPath string) (*pgxpool.Pool, func()) {
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

	pool := database.NewPgxConnPool(database.PoolConfig{
		MaxOpenConns:    5,
		ConnMaxIdleTime: 5 * time.Minute,
		ConnMaxLifetime: 30 * time.Minute,
		User:            dbUser,
		DBName:          dbName,
		Password:        dbPassword,
		Host:            host,
		Port:            port.Port(),
	})
	return pool, terminate
}
