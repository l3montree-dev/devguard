// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/daemon"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"

	_ "github.com/lib/pq"
)

var release string // Will be filled at build time

//	@title			devguard API
//	@version		v1
//	@description	devguard API

//	@contact.name	Support
//	@contact.url	https://github.com/l3montree-dev/devguard/issues

//	@license.name	AGPL-3
//	@license.url	https://github.com/l3montree-dev/devguard/blob/main/LICENSE.txt

// @host		localhost:8080
// @BasePath	/api/v1
func main() {
	//os.Setenv("TZ", "UTC")
	core.LoadConfig() // nolint: errcheck
	core.InitLogger()

	if os.Getenv("ERROR_TRACKING_DSN") != "" {
		initSentry()

		// Catch panics
		defer func() {
			if err := recover(); err != nil {
				// This is a catch-all. To see the stack trace in GlitchTip open the Stacktrace below
				sentry.CurrentHub().Recover(err)
				// Wait for events to be send to server
				sentry.Flush(time.Second * 5)
			}
		}()
	}

	// Initialize database connection first
	db, err := core.DatabaseFactory()
	if err != nil {
		slog.Error(err.Error()) // print detailed error message to stdout
		panic(errors.New("Failed to setup database connection"))
	}

	// Run database migrations using the existing database connection
	autoMigrate := os.Getenv("AUTO_MIGRATE")
	if autoMigrate == "" || autoMigrate == "true" {
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
		slog.Info("automatic migrations disabled via AUTO_MIGRATE=false")
	}

	daemon.Start(db)

	api.Start(db)
}

func initSentry() {

	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "dev"
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:         os.Getenv("ERROR_TRACKING_DSN"),
		Environment: environment,
		Release:     release,

		// In debug mode, the debug information is printed to stdout to help you
		// understand what Sentry is doing.
		Debug: environment == "dev",

		// Configures whether SDK should generate and attach stack traces to pure
		// capture message calls.
		AttachStacktrace: true,

		// If this flag is enabled, certain personally identifiable information (PII) is added by active integrations.
		// By default, no such data is sent.
		SendDefaultPII: false,
	})
	if err != nil {
		slog.Error("Failed to init logger", "err", err)
	}
}
