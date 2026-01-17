// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/cmd/devguard-cli/hashmigrations"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func NewMigrateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run all database migrations",
		Long: `Runs all pending database migrations (schema and hash migrations).
This command is designed to be run as a Kubernetes init container to ensure
the database is fully migrated before the main application starts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			return runMigrations()
		},
	}
}

func runMigrations() error {
	// Step 1: Run schema migrations
	slog.Info("running database schema migrations...")
	if err := database.RunMigrations(nil); err != nil {
		slog.Error("schema migration failed", "err", err)
		return err
	}
	slog.Info("schema migrations completed successfully")

	// Step 2: Run hash migrations (requires full dependency graph)
	var migrationErr error

	app := fx.New(
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.NopLogger,
		database.Module,
		fx.Provide(database.NewPostgreSQLBroker),
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		controllers.ControllerModule,
		integrations.Module,
		vulndb.Module,
		daemons.Module,

		fx.Invoke(func(
			pool *pgxpool.Pool,
			daemonRunner shared.DaemonRunner,
		) {
			slog.Info("checking if hash migrations are needed...")
			start := time.Now()

			if err := hashmigrations.RunHashMigrationsIfNeeded(pool, daemonRunner); err != nil {
				slog.Error("hash migration failed", "err", err)
				migrationErr = err
				return
			}

			slog.Info("hash migration check completed", "duration", time.Since(start))
		}),
	)

	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		return err
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := app.Stop(stopCtx); err != nil {
		return err
	}

	return migrationErr
}
