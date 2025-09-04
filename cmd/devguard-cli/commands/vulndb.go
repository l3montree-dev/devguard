package commands

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

var primaryKeysFromTables = map[string][]string{"cves": {"cve"}, "cwes": {"cwe"}, "affected_components": {"id"}, "cve_affected_component": {"affected_component_id", "cvecve"}, "exploits": {"id"}}

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newImportCVECommand())
	vulndbCmd.AddCommand(newSyncCommand())
	vulndbCmd.AddCommand(newImportCommand())
	vulndbCmd.AddCommand(newExportIncrementalCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	return slices.Contains(s, e)
}

func isValidCVE(cveID string) bool {
	// should either be just 2023-1234 or cve-2023-1234
	if len(cveID) == 0 {
		return false
	}

	r := regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	if r.MatchString(cveID) {
		return true
	}

	r = regexp.MustCompile(`^\d{4}-\d{4,7}$`)
	return r.MatchString(cveID)
}

func migrateDB(db core.DB) {
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if err := database.RunMigrationsWithDB(db); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		// Run hash migrations if needed (when algorithm version changes)
		if err := models.RunHashMigrationsIfNeeded(db); err != nil {
			slog.Error("failed to run hash migrations", "error", err)
			panic(errors.New("Failed to run hash migrations"))
		}
	} else {
		slog.Info("automatic migrations disabled via DISABLE_AUTOMIGRATE=true")
	}
}

func newImportCVECommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import-cve",
		Short: "Will import the vulnerability database",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			db, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			cveID := args[0]
			cveID = strings.TrimSpace(strings.ToUpper(cveID))
			// check if first argument is valid cve
			if !isValidCVE(cveID) {
				slog.Error("invalid cve id", "cve", cveID)
				return
			}

			cveRepository := repositories.NewCVERepository(db)
			nvdService := vulndb.NewNVDService(cveRepository)
			osvService := vulndb.NewOSVService(repositories.NewAffectedComponentRepository(db))

			cve, err := nvdService.ImportCVE(cveID)

			if err != nil {
				slog.Error("could not import cve", "err", err)
				return
			}
			slog.Info("successfully imported cve", "cveID", cve.CVE)

			// the cvelist does provide additional cpe matches.
			cvelistService := vulndb.NewCVEListService(cveRepository)
			cpeMatches, err := cvelistService.ImportCVE(cveID)
			if err != nil {
				slog.Error("could not import cve from cvelist", "err", err)
				return
			}

			slog.Info("successfully imported cpe matches", "cveID", cve.CVE, "cpeMatches", len(cpeMatches))

			// the osv database provides additional information about affected packages
			affectedPackages, err := osvService.ImportCVE(cveID)
			if err != nil {
				slog.Error("could not import cve from osv", "err", err)
				return
			}

			slog.Info("successfully imported affected packages", "cveID", cve.CVE, "affectedPackages", len(affectedPackages))
		},
	}

	return importCmd
}

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Will import the vulnerability database",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				slog.Error("missing mode choose <inc> for incremental updates (recommended) or <full> to copy the full vuln database")
				return
			}
			mode := args[0]
			core.LoadConfig() // nolint

			if mode == "inc" {
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
				config.MaxConns = 10
				config.MinConns = 2

				pool, err := pgxpool.NewWithConfig(ctx, config)

				if err != nil {
					log.Fatalf("Unable to create connection pool: %v", err)
				}
				defer pool.Close()
				// only import the incremental updates
				// pull incremental files from github database
				files, err := os.ReadDir("vulndb-tmp")
				if err != nil {
					slog.Error("error when reading dir", "error", err)
					return
				}

				for _, file := range files {
					name := file.Name()
					if filepath.Ext(name) != ".csv" {
						continue
					}
					name = strings.TrimRight(name, ".csv")
					fields := strings.Split(name, "_")
					if len(fields) != 3 || fields[1] != "diff" {
						continue
					}
					mode := fields[2]
					table := fields[0]
					switch mode {
					case "insert":
						slog.Info("start inserting", "file", name)
						err = processInsertDiff(ctx, pool, "vulndb-tmp/"+name+".csv", table)
						if err != nil {
							continue
						}
					case "delete":
						slog.Info("start deleting", "file", name)
						err = processDeleteDiff(ctx, pool, "vulndb-tmp/"+name+".csv", table)
						if err != nil {
							continue
						}
					case "update":
						slog.Info("start updating", "file", name)
						err = processUpdateDiff(ctx, pool, "vulndb-tmp/"+name+".csv", table)
						if err != nil {
							continue
						}
					default:
						slog.Warn("invalid mode for diff file")
					}
				}
				return
			} else if mode == "full" { // import the full table
				database, err := core.DatabaseFactory()
				if err != nil {
					slog.Error("could not connect to database", "error", err)
					return
				}
				migrateDB(database)

				cveRepository := repositories.NewCVERepository(database)
				cweRepository := repositories.NewCWERepository(database)
				exploitsRepository := repositories.NewExploitRepository(database)
				affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)

				tag := "latest"
				if len(args) > 1 {
					tag = args[1]
				}
				v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)
				err = v.Import(database, tag)
				if err != nil {
					slog.Error("could not import vulndb", "err", err)
					return
				}
			} else { // invalid argument
				slog.Error("invalid first argument, most be 'inc' to only import the difference or 'full' to import the whole table")
				return
			}
			return
		},
	}
	return importCmd
}

func processInsertDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	if tableName != "cves" {
		return nil
	}
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Conn().Close(ctx)
	slog.Info("start copying")
	result, err := conn.Conn().PgConn().CopyFrom(ctx, fd, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true, NULL 'NULL')", tableName))
	if err != nil {
		slog.Error("TOT", "err", err, "result", result)
		return err
	}
	slog.Info("finished copying")

	return nil
}

func processDeleteDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	if tableName != "cves" {
		return nil
	}
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Conn().Close(ctx)

	csvReader := csv.NewReader(fd)
	allRecords, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	primaryKey := allRecords[0][0]
	allRecords = allRecords[1:]
	slog.Info("start deleting")
	for i := range allRecords {
		key := allRecords[i][0]
		sql := fmt.Sprintf("DELETE FROM %s WHERE %s.%s = %s", tableName, tableName, primaryKey, "'"+key+"'")
		result, err := conn.Exec(ctx, sql)
		if err != nil {
			slog.Error("TOT", "err", err, "result", result)
			continue
		}
	}
	slog.Info("finished deleting")

	return nil
}

func processUpdateDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	if tableName != "cves" {
		return nil
	}
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Conn().Close(ctx)

	csvReader := csv.NewReader(fd)
	record, err := csvReader.Read()
	if err != nil {
		return err
	}
	columnsToUpdate := record[1:] // exclude primary key(s)
	for i, column := range columnsToUpdate {
		if column == "references" {
			columnsToUpdate[i] = fmt.Sprintf("\"%s\" = EXCLUDED.%s", column, column)
		} else {
			columnsToUpdate[i] = fmt.Sprintf("%s = EXCLUDED.%s", column, column)
		}
	}
	assignSQL := strings.Join(columnsToUpdate, ", ")

	tmpTable := tableName + "_tmp_" + strconv.Itoa(time.Now().Second())

	_, err = conn.Conn().Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", tmpTable, tableName))
	if err != nil {
		return fmt.Errorf("failed to create tmp table: %w", err)
	}
	defer conn.Conn().Exec(ctx, fmt.Sprintf("DROP TABLE %s;", tmpTable))
	fd, err = os.Open(filePath)
	if err != nil {
		return err
	}

	_, err = conn.Conn().PgConn().CopyFrom(ctx, fd, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true, NULL 'NULL')", tmpTable))
	if err != nil {
		return fmt.Errorf("failed to copy to tmp table: %w", err)
	}

	pkeys := primaryKeysFromTables[tableName]

	upsertSQL := fmt.Sprintf("INSERT INTO %s SELECT * FROM %s ON CONFLICT (%s) DO UPDATE SET %s", tableName, tmpTable, pkeys[0], assignSQL)

	if _, err := conn.Exec(ctx, upsertSQL); err != nil {
		return err
	}
	slog.Info("update completed")

	return nil
}

func newSyncCommand() *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "sync",
		Short: "Will sync the vulnerability database",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// check if after flag is set
			after, _ := cmd.Flags().GetString("after")
			startIndex, _ := cmd.Flags().GetInt("startIndex")

			core.LoadConfig() // nolint

			db, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(db)
			cweRepository := repositories.NewCWERepository(db)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(db)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)
			// cvelistService := vulndb.NewCVEListService(cveRepository)
			debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			expoitDBService := vulndb.NewExploitDBService(nvdService, repositories.NewExploitRepository(db))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(db))

			if emptyOrContains(databasesToSync, "cwe") {
				now := time.Now()
				slog.Info("starting cwe database sync")
				if err := mitreService.Mirror(); err != nil {
					slog.Error("could not mirror cwe database", "err", err)
				}
				slog.Info("finished cwe database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "nvd") {
				slog.Info("starting nvd database sync")
				now := time.Now()
				if after != "" {
					// we do a partial sync
					// try to parse the date
					afterDate, err := time.Parse("2006-01-02", after)
					if err != nil {
						slog.Error("could not parse after date", "err", err, "provided", after, "expectedFormat", "2006-01-02")
					}
					err = nvdService.FetchAfter(afterDate)
					if err != nil {
						slog.Error("could not fetch after date", "err", err)
					}
				} else {
					if startIndex != 0 {
						err = nvdService.FetchAfterIndex(startIndex)
						if err != nil {
							slog.Error("could not fetch after index", "err", err)
						}
					} else {
						err = nvdService.Sync()
						if err != nil {
							slog.Error("could not do initial sync", "err", err)
						}
					}
				}
				slog.Info("finished nvd database sync", "duration", time.Since(now))
			}

			/*if emptyOrContains(databasesToSync, "cvelist") {
				slog.Info("starting cvelist database sync")
				now := time.Now()

				if err := cvelistService.Mirror(); err != nil {
					slog.Error("could not mirror cvelist database", "err", err)
				}
				slog.Info("finished cvelist database sync", "duration", time.Since(now))
			}*/

			if emptyOrContains(databasesToSync, "epss") {
				slog.Info("starting epss database sync")
				now := time.Now()

				if err := epssService.Mirror(); err != nil {
					slog.Error("could not sync epss database", "err", err)
				}
				slog.Info("finished epss database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "osv") {
				slog.Info("starting osv database sync")
				now := time.Now()
				if err := osvService.Mirror(); err != nil {
					slog.Error("could not sync osv database", "err", err)
				}
				slog.Info("finished osv database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "exploitdb") {
				slog.Info("starting exploitdb database sync")
				now := time.Now()
				if err := expoitDBService.Mirror(); err != nil {
					slog.Error("could not sync exploitdb database", "err", err)
				}
				slog.Info("finished exploitdb database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "github-poc") {
				slog.Info("starting github-poc database sync")
				now := time.Now()
				if err := githubExploitDBService.Mirror(); err != nil {
					slog.Error("could not sync github-poc database", "err", err)
				}
				slog.Info("finished github-poc database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "dsa") {
				slog.Info("starting dsa database sync")
				now := time.Now()
				if err := debianSecurityTracker.Mirror(); err != nil {
					slog.Error("could not sync dsa database", "err", err)
				}
				slog.Info("finished dsa database sync", "duration", time.Since(now))
			}
		},
	}
	syncCmd.Flags().String("after", "", "allows to only sync a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	syncCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")
	syncCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to sync. Possible values are: nvd, cvelist, exploitdb, github-poc, cwe, epss, osv, dsa")

	return &syncCmd
}

func newExportIncrementalCommand() *cobra.Command {
	exportCmd := cobra.Command{
		Use:   "export",
		Short: "Will import the new vuln db after sync and export the diff of the old and new state of the vuln db",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// first import the new state
			core.LoadConfig() // nolint

			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)

			tag := "latest"
			if len(args) > 0 {
				tag = args[0]
			}
			os.Setenv("MAKE_TABLE_DIFF", "true")
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)
			err = v.Import(database, tag)
			if err != nil {
				slog.Error("could not import vulndb", "err", err)
				return
			}
		},
	}
	return &exportCmd
}
