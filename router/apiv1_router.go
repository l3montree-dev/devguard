package router

import (
	"encoding/json"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Copyright (C) 2025 l3montree GmbH
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

type APIV1Router struct {
	*echo.Group
}

func NewAPIV1Router(srv api.Server,
	db shared.DB,
	pool *pgxpool.Pool,
	thirdPartyIntegration shared.IntegrationAggregate,
	oryAdmin shared.AdminClient,
	assetController *controllers.AssetController,
	intotoController *controllers.InToToController,
	csafController *controllers.CSAFController,
	orgRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetRepository shared.AssetRepository,
	assetVersionRepository shared.AssetVersionRepository,
	artifactRepository shared.ArtifactRepository,
) APIV1Router {
	apiV1Router := srv.Echo.Group("/api/v1")
	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
			return next(ctx)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			// set the ory admin client to the context
			shared.SetAuthAdminClient(ctx, oryAdmin)
			return next(ctx)
		}
	})

	apiV1Router.GET("/info/", func(c echo.Context) error {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		// Build the response with typed structs
		resp := InfoResponse{
			Build: BuildInfo{
				Version:   config.Version,
				Commit:    config.Commit,
				Branch:    config.Branch,
				BuildDate: config.BuildDate,
			},
			Runtime: RuntimeInfo{
				GoVersion:     runtime.Version(),
				NumGoroutines: runtime.NumGoroutine(),
				Mem: MemStats{
					Alloc:      mem.Alloc,
					TotalAlloc: mem.TotalAlloc,
					Sys:        mem.Sys,
					HeapAlloc:  mem.HeapAlloc,
				},
			},
			Process: ProcessInfo{
				PID:           os.Getpid(),
				UptimeSeconds: int(time.Since(api.StartedAt).Seconds()),
			},
		}

		host, _ := os.Hostname()
		if host != "" {
			resp.Process.Hostname = host
		}

		// DB connectivity & migration info
		// Prepare pool config and a working PoolInfo to fill in later
		poolCfg := database.GetPoolConfigFromEnv()
		poolInfo := PoolInfo{
			DBName:          poolCfg.DBName,
			MaxOpenConns:    poolCfg.MaxOpenConns,
			ConnMaxLifetime: poolCfg.ConnMaxLifetime.String(),
			ConnMaxIdleTime: poolCfg.ConnMaxIdleTime.String(),
		}

		dbInfo := DatabaseInfo{Status: "unknown"}
		sqlDB, err := db.DB()
		if err != nil {
			errMsg := "failed to get database instance"
			dbInfo.Status = "unhealthy"
			dbInfo.Error = &errMsg
		} else {
			if err := sqlDB.Ping(); err != nil {
				errMsg := "database ping failed"
				dbInfo.Status = "unhealthy"
				dbInfo.Error = &errMsg
			} else {
				dbInfo.Status = "healthy"

				// Prefer runtime stats from the underlying pgx pool which backs the sql.DB
				if pool != nil {
					stats := pool.Stat()
					// Map pgx pool stats to the DBStats fields
					dbInfo.OpenConnections = int(stats.TotalConns())
					dbInfo.InUse = int(stats.AcquiredConns())
					dbInfo.Idle = int(stats.IdleConns())
					dbInfo.MaxOpenConnections = int(stats.MaxConns())

					// Expose the same values in the Pool info structure below
					poolInfo.TotalConns = int(stats.TotalConns())
					poolInfo.IdleConns = int(stats.IdleConns())
					poolInfo.AcquiredConns = int(stats.AcquiredConns())
					poolInfo.MaxConns = int(stats.MaxConns())
				} else {
					// Fallback to sql DB stats if pool isn't available
					dbInfo.DBStats = sqlDB.Stats()
				}

				if ver, dirty, err := database.GetMigrationVersionWithDB(db); err == nil {
					v := ver
					dbInfo.MigrationVersion = &v
					dbInfo.MigrationDirty = &dirty
				} else {
					errStr := err.Error()
					dbInfo.MigrationError = &errStr
				}

				// vulndb last imported version from config
				var cfg models.Config
				if err := db.Where("key = ?", "vulndb.lastIncrementalImport").First(&cfg).Error; err == nil {
					var last string
					if err := json.Unmarshal([]byte(cfg.Val), &last); err == nil {
						dbInfo.VulnDBVersion = &last
					} else {
						copy := cfg.Val
						dbInfo.VulnDBVersion = &copy
					}
				}
			}
		}
		// attach pool config for diagnostics (no sensitive fields)
		resp.Database.Pool = &poolInfo

		resp.Database = dbInfo

		return c.JSON(200, resp)
	})

	apiV1Router.GET("/metrics/", echo.WrapHandler(promhttp.Handler()))
	apiV1Router.GET("/health/", func(ctx echo.Context) error {
		// Check database connectivity
		sqlDB, err := db.DB()
		if err != nil {
			return ctx.JSON(503, map[string]string{
				"status": "unhealthy",
				"error":  "failed to get database instance",
			})
		}

		if err := sqlDB.Ping(); err != nil {
			return ctx.JSON(503, map[string]string{
				"status": "unhealthy",
				"error":  "database ping failed",
			})
		}

		return ctx.JSON(200, map[string]string{
			"status": "healthy",
		})
	})
	apiV1Router.GET("/badges/:badge/:badgeSecret/", assetController.GetBadges)
	apiV1Router.GET("/lookup/", assetController.HandleLookup)
	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)
	apiV1Router.POST("/webhook/", thirdPartyIntegration.HandleWebhook)

	// csaf routes
	apiV1Router.GET("/.well-known/csaf-aggregator/aggregator.json/", csafController.GetAggregatorJSON)
	apiV1Router.GET("/organizations/:organization/csaf/provider-metadata.json/", csafController.GetProviderMetadataForOrganization, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/", csafController.GetOpenPGPHTML, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/:file/", csafController.GetOpenPGPFile, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))

	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/", csafController.GetCSAFIndexHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/index.txt/", csafController.GetIndexFile, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/changes.csv/", csafController.GetChangesCSVFile, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/", csafController.GetTLPWhiteEntriesHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/", csafController.GetReportsByYearHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/:version/", csafController.ServeCSAFReportRequest, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	return APIV1Router{
		Group: apiV1Router,
	}
}
