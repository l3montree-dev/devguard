package tests

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
)

func TestOSVPostInsertCleanup(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("after inserting using the bulk method, we should have all indexes and constraints back in place correctly", func(t *testing.T) {
			// this test is used to make sure that all indexes and constraints are dropped which are not needed on bulk inserts
			// if you happen to fail this test, just make sure to add the sql to drop your index/constraint in the PrepareBulkInsert-Functions sql scripts
			// then also re-add it in the AddIndexesAndConstraints-Function sql scripts just the same as you added it in the migrations
			// this should then pass the test again

			ctx := context.Background()

			conn, err := f.Pool.Acquire(ctx)
			assert.NoError(t, err)

			tx, err := conn.Begin(ctx)
			assert.NoError(t, err)

			constraintsPerTable, indexesPerTable, err := getCurrentIndexAndConstraintState(ctx, tx)
			assert.NoError(t, err)

			err = vulndb.PrepareBulkInsert(ctx, tx)
			assert.NoError(t, err)

			cleanedConstraints, cleanedIndexes, err := getCurrentIndexAndConstraintState(ctx, tx)
			assert.NoError(t, err)
			assert.Len(t, cleanedIndexes, 2, "only the primary key indexes of cves and cve_relationships should remain for the import to detect ON CONFLICT triggers")
			for table, indexes := range cleanedIndexes {
				if table == "cves" || table == "cve_relationships" {
					assert.Len(t, indexes, 1)
					assert.Equal(t, table+"_pkey", indexes[0])
				} else {
					t.Fail()
				}
			}
			for table, constraints := range cleanedConstraints {
				switch table {
				case "cves", "cve_relationships":
					assert.Equal(t, 1, amountOfNonNotNullConstraintsInSlice(constraints), "the primary key should still be in place as previously mentioned")
				case "affected_components", "cve_affected_component":
					assert.Equal(t, 0, amountOfNonNotNullConstraintsInSlice(constraints), "for the other tables all non not_null constraints should be removed")
				default:
					t.Fail()
				}
			}
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

func amountOfNonNotNullConstraintsInSlice(constraints []string) int {
	amount := 0
	for _, constraint := range constraints {
		if !strings.Contains(constraint, "not_null") {
			amount++
		}
	}
	return amount
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
