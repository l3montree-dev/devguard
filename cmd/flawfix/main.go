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
	"io"
	"os"
	"time"

	"github.com/joho/godotenv"
	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/controller"
	appMiddleware "github.com/l3montree-dev/flawfix/internal/middleware"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/owenrumney/go-sarif/sarif"

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

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 10 * time.Second,
	}))

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		c.Logger().Error(err)
		e.DefaultHTTPErrorHandler(err, c)
	}

	appRepository := repositories.NewGormApplicationRepository(db)
	reportRepository := repositories.NewGormReportRepository(db, appRepository)
	organizationRepository := repositories.NewGormOrganizationRepository(db)

	organizationController := controller.NewOrganizationController(organizationRepository, casbinRBACProvider)

	// apply the health route without any session or multi tenant middleware
	e.GET("/api/v1/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// use the organization router for creating a new organization - this is not multi tenant
	orgRouter := e.Group("/api/v1/organization", appMiddleware.SessionMiddleware(ory))
	orgRouter.POST("/", organizationController.Create)

	appRouter := e.Group("/api/v1/:tenant", appMiddleware.SessionMiddleware(ory), appMiddleware.MultiTenantMiddleware(casbinRBACProvider, organizationRepository))

	appRouter.POST("/reports", func(c echo.Context) error {
		// print the request body as string
		reportStr, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		report, err := sarif.FromBytes(reportStr)
		if err != nil {
			return err
		}
		// save the report inside the database
		err = reportRepository.SaveSarifReport("test", report)

		if err != nil {
			return err
		}

		return c.String(200, "ok")
	})

	e.Logger.Fatal(e.Start(":8080"))
}
