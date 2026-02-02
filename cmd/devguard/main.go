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
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/vulndb"

	"github.com/l3montree-dev/devguard/router"
	"github.com/l3montree-dev/devguard/services"

	"github.com/l3montree-dev/devguard/database"

	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"

	_ "net/http/pprof"

	_ "github.com/lib/pq"
)

var release string // Will be filled at build time

//	@title			DevGuard API
//	@version		v1
//	@description	DevGuard Backend. Secure your Software Supply Chain. Attestation-based compliance as Code, manage your CVEs seamlessly, Integrate your Vulnerability Scanners, Security Framework Documentation made easy. OWASP Incubating Project

//	@contact.name	Support
//	@contact.url	https://github.com/l3montree-dev/devguard/issues

//	@license.name	AGPL-3
//	@license.url	https://github.com/l3montree-dev/devguard/blob/main/LICENSE.txt

// @servers.url {scheme}://{host}:{port}/api/v1
// @servers.description Development server
// @servers.variables.enum scheme http
// @servers.variables.enum scheme https
// @servers.variables.default scheme http
// @servers.variables.default host localhost
// @servers.variables.default port 8080

// @servers.url https://api.devguard.org/api/v1
// @servers.description Production server

//	@securityDefinitions.apikey	CookieAuth
//	@in							cookie
//	@name						ory_kratos_session
//	@description				Session-based authentication using Ory Kratos

// @securityDefinitions.apikey	PATAuth
// @in							header
// @name						X-Signature
// @description				Personal Access Token authentication using HTTP request signing. Requires X-Signature and X-Fingerprint headers.
func main() {
	//os.Setenv("TZ", "UTC")
	shared.LoadConfig() // nolint: errcheck
	shared.InitLogger()

	if os.Getenv("ERROR_TRACKING_DSN") != "" {
		initSentry()

		// Catch panics
		defer func() {
			if err := recover(); err != nil {
				// This is a catch-all. To see the stack trace in GlitchTip open the Stacktrace below
				sentry.CurrentHub().Recover(err)
				monitoring.RecoverAndAlert("could not recover from panic in main", fmt.Errorf("panic: %v", err))
				sentry.Flush(time.Second * 5)
			}
		}()
	}

	app := fx.New(
		fx.NopLogger,
		fx.Supply(database.GetPoolConfigFromEnv()),
		fx.Provide(api.NewServer),
		database.Module,
		repositories.Module,
		controllers.ControllerModule,
		services.ServiceModule,
		router.RouterModule,
		accesscontrol.AccessControlModule,
		integrations.Module,
		vulndb.Module,
		daemons.Module,
		// we need to invoke all routers to register their routes
		fx.Invoke(func(OrgRouter router.OrgRouter) {}),
		fx.Invoke(func(ProjectRouter router.ProjectRouter) {}),
		fx.Invoke(func(SessionRouter router.SessionRouter) {}),
		fx.Invoke(func(ArtifactRouter router.ArtifactRouter) {}),
		fx.Invoke(func(AssetRouter router.AssetRouter) {}),
		fx.Invoke(func(AssetVersionRouter router.AssetVersionRouter) {}),
		fx.Invoke(func(DependencyVulnRouter router.DependencyVulnRouter) {}),
		fx.Invoke(func(FirstPartyVulnRouter router.FirstPartyVulnRouter) {}),
		fx.Invoke(func(LicenseRiskRouter router.LicenseRiskRouter) {}),
		fx.Invoke(func(ShareRouter router.ShareRouter) {}),
		fx.Invoke(func(VulnDBRouter router.VulnDBRouter) {}),
		fx.Invoke(func(dependencyProxyRouter router.DependencyProxyRouter) {}),
		fx.Invoke(func(FalsePositiveRuleRouter router.VEXRuleRouter) {}),
		fx.Invoke(func(ExternalReferenceRouter router.ExternalReferenceRouter) {}),
		fx.Invoke(func(lc fx.Lifecycle, server api.Server) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					go server.Start() // start in background
					return nil
				},
			})
		}),
		fx.Invoke(func(lc fx.Lifecycle, daemonRunner shared.DaemonRunner) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					go daemonRunner.Start() // start in background
					return nil
				},
			})
		}),
	)

	app.Run()
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

// AllModules combines all FX modules for easy import
var AllModules = fx.Options(
	controllers.ControllerModule,
	services.ServiceModule,
)
