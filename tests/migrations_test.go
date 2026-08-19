package tests

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/l3montree-dev/devguard/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunMigrations(t *testing.T) {
	pool, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	ctx := context.Background()
	db := database.NewGormDB(pool)

	require.NoError(t, database.RunMigrations(db))
	require.NoError(t, database.RunMigrations(db))

	var version int
	var dirty bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT version, dirty FROM public.schema_migrations`).Scan(&version, &dirty))
	assert.GreaterOrEqual(t, version, 20260818140001)
	assert.False(t, dirty)
}

func TestRunMigrationsFromSourceRollsBackOnFailure(t *testing.T) {
	pool, terminate := InitRawDatabaseContainer("../initdb.sql")
	defer terminate()

	ctx := context.Background()
	db := database.NewGormDB(pool)

	fakeMigrations := fstest.MapFS{
		"1_ok.up.sql":  {Data: []byte(`CREATE TABLE public.migration_test_a (id int);`)},
		"2_bad.up.sql": {Data: []byte(`CREATE TABLE public.migration_test_b (id int); SELECT 1/0;`)},
	}
	src, err := iofs.New(fakeMigrations, ".")
	require.NoError(t, err)
	defer src.Close()

	require.Error(t, database.RunMigrationsFromSource(db, src))

	var exists bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'migration_test_a')`).Scan(&exists))
	assert.False(t, exists, "migration 1 succeeded but must be rolled back with migration 2's failure")

	var rowCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM public.schema_migrations`).Scan(&rowCount))
	assert.Equal(t, 0, rowCount, "bookkeeping must not advance when the batch fails")

	fakeMigrations["2_bad.up.sql"] = &fstest.MapFile{Data: []byte(`CREATE TABLE public.migration_test_b (id int);`)}
	require.NoError(t, database.RunMigrationsFromSource(db, src))
}
