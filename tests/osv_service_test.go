package tests

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
)

func TestOSVPostInsertCleanup(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("after inserting using the bulk method, we should have all indexes and constraints back in place correctly", func(t *testing.T) {
			ctx := context.Background()

			conn, err := f.Pool.Acquire(ctx)
			assert.NoError(t, err)

			tx, err := conn.Begin(ctx)
			assert.NoError(t, err)

			constraintsPerTable, indexesPerTable, err := getCurrentIndexAndConstraintState(ctx, tx)
			assert.NoError(t, err)

			err = vulndb.PrepareBulkInsert(ctx, tx)
			assert.NoError(t, err)

			err = vulndb.AddIndexesAndConstraints(ctx, tx)
			assert.NoError(t, err)

			newConstraintsPerTable, newIndexesPerTable, err := getCurrentIndexAndConstraintState(ctx, tx)
			assert.NoError(t, err)

			// now compare both sets; check if each of the old constraints and indexes is still there
			for tableName, constraints := range constraintsPerTable {
				for _, constraint := range constraints {
					assert.True(t, slices.Contains(newConstraintsPerTable[tableName], constraint))
				}
			}

			for tableName, indexes := range indexesPerTable {
				for _, index := range indexes {
					assert.True(t, slices.Contains(newIndexesPerTable[tableName], index))
				}
			}

			slog.Info("finished")
		})
	})
}

func getCurrentIndexAndConstraintState(ctx context.Context, tx pgx.Tx) (map[string][]string, map[string][]string, error) {
	type constraintForTable struct {
		TableName      string
		ConstraintName string
	}
	type indexForTable struct {
		TableName string
		IndexName string
	}

	// get the initial state for the constraints
	constraintRows, err := tx.Query(ctx, `
			SELECT
				table_name, constraint_name
			FROM
				information_schema.table_constraints
			WHERE
				table_name IN ('cves','cve_relationships','affected_components','cve_affected_component');`)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get current constraint state: %w", err)
	}
	constraints, err := pgx.CollectRows(constraintRows, func(row pgx.CollectableRow) (constraintForTable, error) {
		var c constraintForTable
		err := row.Scan(&c.TableName, &c.ConstraintName)
		return c, err
	})
	if err != nil {
		return nil, nil, err
	}

	// get the initial state for the indexes
	indexRows, err := tx.Query(ctx, `
			SELECT
				tablename, indexname
			FROM
				pg_catalog.pg_indexes
			WHERE
				tablename IN ('cves','cve_relationships','affected_components','cve_affected_component');`)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get current index state: %w", err)
	}
	indexes, err := pgx.CollectRows(indexRows, func(row pgx.CollectableRow) (indexForTable, error) {
		var i indexForTable
		err := row.Scan(&i.TableName, &i.IndexName)
		return i, err
	})
	if err != nil {
		return nil, nil, err
	}

	constraintsPerTable := make(map[string][]string, 4)
	indexesPerTable := make(map[string][]string, 4)

	for _, constraint := range constraints {
		constraintsPerTable[constraint.TableName] = append(constraintsPerTable[constraint.TableName], constraint.ConstraintName)
	}

	for _, index := range indexes {
		indexesPerTable[index.TableName] = append(indexesPerTable[index.TableName], index.IndexName)
	}
	return constraintsPerTable, indexesPerTable, nil
}
