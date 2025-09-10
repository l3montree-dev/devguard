package vulndb

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var tablesToUpdate = []string{"cves", "cwes", "affected_components", "cve_affected_component", "exploits"}

func Export() error {
	username := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	// replace with your PostgreSQL connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", username, password, host, port, dbname)

	// create a connection pool with increased connections for parallel processing
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Unable to parse config: %v", err)
	}

	// increase pool size for parallel operations
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		slog.Error("error when trying to create conn pool", "err", err)
		return err
	}
	defer pool.Close()

	dirName := "diffs-tmp"
	err = os.Mkdir(dirName, os.ModePerm)
	if err != nil {
		return err
	}

	for _, table := range tablesToUpdate {
		err = createDiffs(ctx, pool, table+"_diff", table)
		if err != nil { // if one table fails we should stop the whole process
			slog.Error("error when trying to calculate diffs", "table", table, "err", err)
			os.RemoveAll("diffs-tmp/")
			return err
		}
	}
	cleanUpTables(ctx, pool) //no lint
	return nil
}

func cleanUpTables(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback(ctx) //nolint
		}
	}()

	for _, table := range tablesToUpdate {
		sql := fmt.Sprintf("DROP TABLE %s_diff", table)
		_, err := tx.Exec(ctx, sql)
		if err != nil {
			slog.Error("error when dropping table", "table", table, "err", err)
			return err
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		slog.Error("error when trying to commit cleanup", "err", err)
		return err
	}
	return nil
}

func createDiffs(ctx context.Context, pool *pgxpool.Pool, shadowTable string, tableName string) error {
	slog.Info("start producing diff tables", "table", tableName)
	dirPath := "diffs-tmp/"
	conn, err := pool.Acquire(ctx) //get a new transaction from the pool
	if err != nil {
		return err
	}
	defer conn.Release()

	primaryKeys := primaryKeysFromTables[tableName] // get the primary key(s) for the table
	if len(primaryKeys) == 0 {
		slog.Error("no primary key found", "table", tableName)
		return fmt.Errorf("no primary key found")
	}

	// query all the entries which are in the new table and not in the old table
	var rows pgx.Rows
	if len(primaryKeys) == 1 {
		rows, err = conn.Query(ctx, fmt.Sprintf("SELECT new.* FROM %s new LEFT JOIN %s old USING (%s) WHERE old.%s IS NULL;", tableName, shadowTable, primaryKeys[0], primaryKeys[0]))
	} else if len(primaryKeys) == 2 {
		rows, err = conn.Query(ctx, fmt.Sprintf("SELECT new.* FROM %s new LEFT JOIN %s old USING (%s) WHERE old.%s IS NULL OR old.%s IS NULL;", tableName, shadowTable, primaryKeys[0]+", "+primaryKeys[1], primaryKeys[0], primaryKeys[1]))
	} else {
		slog.Error("3 or more primary keys in a table are not currently implemented", "table", tableName)
		return fmt.Errorf("3 or more primary keys in a table are not currently implemented")
	}
	if err != nil {
		return err
	}

	//create insert diff
	err = rowsToCSV(rows, dirPath+tableName+"_diff_insert")
	rows.Close()
	if err != nil {
		return err
	}

	// query all the entries which are not in the new table but in the old table
	if len(primaryKeys) == 1 {
		rows, err = conn.Query(ctx, fmt.Sprintf("SELECT old.* FROM %s old LEFT JOIN %s new USING (%s) WHERE new.%s IS NULL;", shadowTable, tableName, primaryKeys[0], primaryKeys[0]))
	} else if len(primaryKeys) == 2 {
		rows, err = conn.Query(ctx, fmt.Sprintf("SELECT old.* FROM %s old LEFT JOIN %s new USING (%s) WHERE new.%s IS NULL OR new.%s IS NULL;", shadowTable, tableName, primaryKeys[0]+", "+primaryKeys[1], primaryKeys[0], primaryKeys[1]))
	}
	if err != nil {
		return err
	}

	// create delete diff
	err = rowsToCSV(rows, dirPath+tableName+"_diff_delete")
	rows.Close()
	if err != nil {
		return err
	}

	// get the relevant attributes which we want to watch if they changed between tables
	columns := relevantAttributesFromTables[tableName]
	if len(columns) == 0 { // some tables only change based on primary keys, hence we don't need to update them
		slog.Info("no update diff table needed", "table", tableName)
		return nil
	}

	// build sql attributes to query on for both tables
	oldFlags := "old." + columns[0]
	shadowFlags := "new." + columns[0]
	for _, column := range columns[1:] {
		oldFlags += ",old." + column
		shadowFlags += ",new." + column
	}

	// query all entries where the primary key is the same but a relevant attribute changed
	rows, err = conn.Query(ctx, fmt.Sprintf(`SELECT new.* FROM %s old
			JOIN %s new USING (%s) WHERE (%s) 
			IS DISTINCT FROM (%s);`, shadowTable, tableName, primaryKeys[0], shadowFlags, oldFlags))
	if err != nil {
		return err
	}

	// create update diffs
	err = rowsToCSV(rows, dirPath+tableName+"_diff_update")
	rows.Close()
	if err != nil {
		return err
	}

	slog.Info("finished producing diff tables", "table", tableName)
	return nil
}

// converts a query from pgx to a csv file
func rowsToCSV(rows pgx.Rows, csvFileName string) error {
	fd, err := os.Create(csvFileName + ".csv")
	if err != nil {
		return err
	}
	defer fd.Close()
	csvWriter := csv.NewWriter(fd)

	// first make the line with the column names
	columnNames := rows.FieldDescriptions()
	headers := make([]string, len(columnNames))
	for i, column := range columnNames {
		headers[i] = column.Name
	}

	err = csvWriter.Write(headers)
	if err != nil {
		return err
	}

	// then write each record into the csv file
	record := make([]string, len(headers))
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			slog.Warn("could not scan row, continuing... ", "file", csvFileName, "err", err)
			continue // continue with the next row maybe in the future count erroneous rows
		}
		for i, value := range values {
			record[i] = anyToString(value)
		}
		err = csvWriter.Write(record)
		if err != nil {
			slog.Warn("could not scan row", "file, continuing...", csvFileName, "err", err)
			continue //continue with the next row
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return err
	}
	return nil
}

// convert common data types to string so it can be written to csv file
func anyToString(value any) string {
	if value == nil {
		return "NULL"
	}
	switch t := value.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		strconv.Itoa(t)
	default:
		b, err := json.Marshal(t)
		if err == nil {
			return string(b)
		}
		return fmt.Sprint(t)
	}
	return "NULL"
}
