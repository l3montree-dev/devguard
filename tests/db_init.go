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
	splitMerkleEdges(db)

	return db, pool, terminate
}

// splitMerkleEdges brings sbom_merkle_edges into the shape hash migration v8
// leaves behind: component_id moved out to sbom_merkle_nodes, so an edge is a
// pure pivot between two node hashes.
//
// The schema migrations still create the pre-split table, and a real instance
// only reaches the split shape by running the hash migrations - which the test
// harness cannot do wholesale, since v4 needs a vulndb service and v7 drops
// component_dependencies out from under the artifact tests. So the one step the
// repositories depend on is applied here instead.
func splitMerkleEdges(db shared.DB) {
	statements := []string{
		`ALTER TABLE public.sbom_merkle_edges DROP CONSTRAINT IF EXISTS sbom_merkle_edges_unique`,
		`ALTER TABLE public.sbom_merkle_edges DROP COLUMN IF EXISTS component_id`,
		`ALTER TABLE public.sbom_merkle_edges
			ADD PRIMARY KEY (subtree_hash, direct_dependency_subtree_hash),
			ADD FOREIGN KEY (subtree_hash)
				REFERENCES public.sbom_merkle_nodes (node_hash),
			ADD FOREIGN KEY (direct_dependency_subtree_hash)
				REFERENCES public.sbom_merkle_nodes (node_hash)`,
		`ALTER TABLE public.sboms
			ADD FOREIGN KEY (root_subtree_hash)
				REFERENCES public.sbom_merkle_nodes (node_hash)`,
		`CREATE INDEX IF NOT EXISTS sbom_merkle_nodes_component_id
			ON public.sbom_merkle_nodes (component_id)`,
	}

	for _, statement := range statements {
		if err := db.Exec(statement).Error; err != nil {
			log.Printf("failed to split merkle edges: %s", err)
			panic(err)
		}
	}
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
