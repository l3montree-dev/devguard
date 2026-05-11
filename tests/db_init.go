package tests

import (
	"context"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func InitDatabaseContainer(initDBSQLPath string) (shared.DB, *pgxpool.Pool, func()) {
	pool, terminate := InitRawDatabaseContainer(initDBSQLPath)
	// Run embedded migrations to ensure the DB schema matches the project's
	// migration files. This creates the tables and constraints consistently
	// for integration tests.
	db := database.NewGormDB(pool)
	if err := database.RunMigrations(db); err != nil {
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

	// The image has a read-only Nix filesystem so docker cp (used by WithInitScripts)
	// cannot write into the container. Instead we bind-mount the init SQL file,
	// mirroring how docker-compose.yaml mounts ./initdb.sql.
	absInitSQL, err := filepath.Abs(initDBSQLPath)
	if err != nil {
		panic("could not resolve initdb SQL path: " + err.Error())
	}
	if _, err := os.Stat(absInitSQL); err != nil {
		panic("initdb SQL file not found: " + absInitSQL)
	}

	postgresC, err := postgres.Run(ctx,
		"ghcr.io/l3montree-dev/devguard/postgresql:v1.3.1",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPassword),
		postgres.BasicWaitStrategies(),
		testcontainers.WithLogger(log.Default()),
		// The postgres module overrides CMD to "postgres -c fsync=off", which drops the
		// image's config_file arg and makes postgres listen only on 127.0.0.1. We restore
		// the config_file so listen_addresses='*' takes effect for port mapping.
		testcontainers.WithCmd("postgres",
			"-c", "config_file=/etc/postgresql/postgresql.conf",
			"-c", "fsync=off",
		),
		testcontainers.WithTmpfs(map[string]string{
			"/run/postgresql": "rw",
		}),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			// Bind-mount the init SQL; WithInitScripts uses docker cp which fails on the
			// read-only Nix filesystem of this image.
			hc.Binds = append(hc.Binds, absInitSQL+":/docker-entrypoint-initdb.d/init.sql:ro")
		}),
	)

	terminate := func() {
		if err := testcontainers.TerminateContainer(postgresC); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}
	if err != nil {
		if postgresC != nil {
			if logs, lerr := postgresC.Logs(ctx); lerr == nil {
				log.Printf("=== container logs ===")
				buf := make([]byte, 64*1024)
				for {
					n, rerr := logs.Read(buf)
					if n > 0 {
						log.Printf("%s", buf[:n])
					}
					if rerr != nil {
						break
					}
				}
				logs.Close()
			}
		}
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
