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
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/events/listeners"
	"github.com/l3montree-dev/devguard/fixedversion"
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

// backfillRiskHistory rebuilds the risk history of every artifact whose rows were written before diffs were stored.
// The rebuild starts at the first stored day, so every vuln is added on the day it appeared and not on the day of the migration.
// An artifact is only rebuilt while none of its rows has a diff, so an interrupted run continues where it stopped.
func backfillRiskHistory(
	ctx context.Context,
	artifactRepository shared.ArtifactRepository,
	riskHistoryRepository shared.ArtifactRiskHistoryRepository,
	statisticsService shared.StatisticsService,
) error {
	artifacts, err := artifactRepository.All(ctx, nil)
	if err != nil {
		slog.Error("could not load artifacts for risk history backfill", "err", err)
		return err
	}

	now := time.Now()
	rebuilt, skipped, failed := 0, 0, 0
	for i, artifact := range artifacts {
		history, err := riskHistoryRepository.GetRiskHistory(ctx, nil, &artifact.ID, artifact.AssetVersionID, time.Time{}, now)
		if err != nil {
			slog.Error("could not load risk history for backfill", "artifact", artifact.ArtifactName, "assetID", artifact.AssetID, "err", err)
			failed++
			continue
		}

		// no history to repair, or the rows already have diffs
		legacy := len(history) > 0
		for _, row := range history {
			if row.DiffAddedDependencyVulns != nil || row.DiffRemovedDependencyVulns != nil {
				legacy = false
				break
			}
		}
		if !legacy {
			skipped++
			continue
		}

		// the history is ordered by day ascending
		firstDay := history[0].Day
		err = artifactRepository.Transaction(ctx, func(tx shared.DB) error {
			return statisticsService.RebuildArtifactRiskHistory(ctx, tx, &artifact, artifact.AssetID, firstDay, now)
		})
		if err != nil {
			slog.Error("could not rebuild risk history", "artifact", artifact.ArtifactName, "assetID", artifact.AssetID, "err", err)
			failed++
			continue
		}
		rebuilt++
		slog.Info("rebuilt risk history", "artifact", artifact.ArtifactName, "assetID", artifact.AssetID, "from", firstDay.Format(time.DateOnly), "progress", i+1, "of", len(artifacts))
	}

	// artifacts that failed keep their old rows and are picked up again by the next run
	slog.Info("risk history backfill finished", "artifacts", len(artifacts), "rebuilt", rebuilt, "skipped", skipped, "failed", failed)
	return nil
}

func runMigrations() error {
	// Step 1: Run schema migrations
	slog.Info("running database schema migrations...")
	if err := database.RunMigrations(nil); err != nil {
		slog.Error("schema migration failed", "err", err)
		return err
	}
	slog.Info("schema migrations completed successfully")

	slog.Info("running river queue migrations...")
	if err := hashmigrations.RunRiverMigrations(); err != nil {
		slog.Error("river migration failed", "err", err)
		return err
	}
	slog.Info("river queue migrations completed successfully")

	// Step 3: Run hash migrations (requires full dependency graph)
	var migrationErr error

	app := fx.New(
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.NopLogger,
		database.Module,
		events.Module,
		fx.Provide(events.NewBroker),
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		controllers.ControllerModule,
		integrations.Module,
		vulndb.Module,
		listeners.Module,
		fixedversion.Module,

		fx.Invoke(func(
			pool *pgxpool.Pool,
			daemonRunner shared.DaemonRunner,
			vulndbService shared.VulnDBService,
			configService shared.ConfigService,
			artifactRepository shared.ArtifactRepository,
			riskHistoryRepository shared.ArtifactRiskHistoryRepository,
			statisticsService shared.StatisticsService,
			dependencyProxySecretService shared.DependencyProxySecretService,
		) {
			slog.Info("checking if hash migrations are needed...")
			start := time.Now()

			if err := hashmigrations.RunHashMigrationsIfNeeded(pool, daemonRunner, vulndbService, configService, dependencyProxySecretService); err != nil {
				slog.Error("hash migration failed", "err", err)
				migrationErr = err
				return
			}

			slog.Info("hash migration check completed", "duration", time.Since(start))

			slog.Info("backfilling risk history...")
			if err := backfillRiskHistory(context.Background(), artifactRepository, riskHistoryRepository, statisticsService); err != nil {
				slog.Error("risk history backfill failed", "err", err)
				migrationErr = err
				return
			}

			db := database.NewGormDB(pool)
			slog.Info("loading compliance controls into database...")
			migrationErr = db.Transaction(func(tx shared.DB) error {
				if err := compliance.LoadControlsIntoDB(tx); err != nil {
					slog.Error("failed to load compliance controls", "err", err)
					return err
				}
				return nil
			})
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
