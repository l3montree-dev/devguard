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

	"github.com/lmittmann/tint"

	"github.com/joho/godotenv"
	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/core"

	"github.com/l3montree-dev/flawfix/internal/core/asset"

	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/org"
	"github.com/l3montree-dev/flawfix/internal/core/pat"
	"github.com/l3montree-dev/flawfix/internal/core/project"
	"github.com/l3montree-dev/flawfix/internal/core/vulnreport"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/echohttp"

	"github.com/labstack/echo/v4"

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

// initLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func initLogger() {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}

func main() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}
	initLogger()
	ory := getOryApiClient()

	db, err := database.NewConnection(os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"), "5432")
	if err != nil {
		panic(err)
	}

	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}

	server := echohttp.Server()

	apiV1Router := server.Group("/api/v1")
	// apply the health route without any session or multi tenant middleware
	apiV1Router.GET("/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	// we need those core features in globally scoped middlewares. Therefore
	// initialize them right here.
	patRepository := pat.NewGormRepository(db)
	assetRepository := asset.NewGormRepository(db)
	projectRepository := project.NewGormRepository(db)
	projectScopedRBAC := project.ProjectAccessControlFactory(projectRepository)

	sessionMiddleware := auth.SessionMiddleware(ory, patRepository)

	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", sessionMiddleware)
	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"userId": core.GetSession(c).GetUserID(),
		})
	})
	vulnreport.RegisterHttpHandler(db, sessionRouter)

	// pat does return a scoped router, but we don't need it here.
	pat.RegisterHttpHandler(db, sessionRouter)

	// each http registration returns its own scoped router.
	// since this asset has a multi tenant and hierarchical structure
	// we need to pass the returned router to the next registration.
	tenantRouter := org.RegisterHttpHandler(db, sessionRouter, casbinRBACProvider)
	projectRouter := project.RegisterHttpHandler(db, tenantRouter, assetRepository)
	assetRouter := asset.RegisterHttpHandler(db, projectRouter, projectScopedRBAC)

	flaw.RegisterHttpHandler(db, assetRouter, projectScopedRBAC)

	slog.Error("failed to start server", "err", server.Start(":8080").Error())
}
