// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"

	"github.com/joho/godotenv"
	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/controller"
	appMiddleware "github.com/l3montree-dev/flawfix/internal/middleware"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	_ "github.com/lib/pq"
	"github.com/ory/client-go"
)

func getOryApiClient() *client.APIClient {
	cfg := client.NewConfiguration()
	cfg.Servers = client.ServerConfigurations{
		{URL: os.Getenv("ORY_KRATOS")},
	}

	ory := client.NewAPIClient(cfg)
	return ory
}

func main() {

	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)

	godotenv.Load()

	ory := getOryApiClient()

	db, err := models.NewConnection(os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"), "5432")
	if err != nil {
		panic(err)
	}

	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}

	e := echo.New()

	e.Use(middleware.CORSWithConfig(
		middleware.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowHeaders:     middleware.DefaultCORSConfig.AllowHeaders,
			AllowMethods:     middleware.DefaultCORSConfig.AllowMethods,
			AllowCredentials: true,
		},
	))

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 10 * time.Second,
	}))

	e.Use(middleware.Recover())

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// do the logging straight inside the error handler
		// this keeps controller methods clean
		slog.Error(err.Error())
		e.DefaultHTTPErrorHandler(err, c)
	}

	appRepository := repositories.NewGormApplicationRepository(db)
	reportRepository := repositories.NewGormReportRepository(db, appRepository)
	organizationRepository := repositories.NewGormOrganizationRepository(db)

	organizationController := controller.NewOrganizationController(organizationRepository, casbinRBACProvider)
	reportController := controller.NewReportController(reportRepository)

	// apply the health route without any session or multi tenant middleware
	e.GET("/api/v1/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// use the organization router for creating a new organization - this is not multi tenant
	e.POST("/api/v1/organizations", organizationController.Create, appMiddleware.SessionMiddleware(ory))
	e.GET("/api/v1/organizations", organizationController.List, appMiddleware.SessionMiddleware(ory))

	tenantRouter := e.Group("/api/v1/organizations/:tenant", appMiddleware.SessionMiddleware(ory), appMiddleware.MultiTenantMiddleware(casbinRBACProvider, organizationRepository))

	tenantRouter.DELETE("/", organizationController.Delete, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", organizationController.Read, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	projectRouter := tenantRouter.Group("/projects/:projectID", appMiddleware.ProjectAccessControl("project", accesscontrol.ActionRead))

	applicationRouter := projectRouter.Group("/applications/:applicationID")

	applicationRouter.POST("/reports", reportController.Create, appMiddleware.ProjectAccessControl("report", accesscontrol.ActionCreate))

	slog.Error("failed to start server", e.Start(":8080").Error())
}
