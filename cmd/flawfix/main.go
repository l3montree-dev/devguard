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
	"encoding/json"
	"log/slog"
	"net/http"
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

func registerMiddlewares(e *echo.Echo) {
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
	e.Use(appMiddleware.Logger())

	e.Use(appMiddleware.Recover())

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// do the logging straight inside the error handler
		// this keeps controller methods clean
		slog.Error(err.Error())

		if c.Response().Committed {
			return
		}

		he, ok := err.(*echo.HTTPError)
		if ok {
			if he.Internal != nil {
				if herr, ok := he.Internal.(*echo.HTTPError); ok {
					he = herr
				}
			}
		} else {
			he = &echo.HTTPError{
				Code:    http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
			}
		}

		code := he.Code
		message := he.Message

		switch m := he.Message.(type) {
		case string:
			if e.Debug {
				message = echo.Map{"message": m, "error": err.Error()}
			} else {
				message = echo.Map{"message": m}
			}
		case json.Marshaler:
			// do nothing - this type knows how to format itself to JSON
		case error:
			message = echo.Map{"message": m.Error()}
		}

		// Send response
		if c.Request().Method == http.MethodHead { // Issue #608
			c.NoContent(he.Code)
		} else {
			c.JSON(code, message)
		}
	}
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
	e.Logger.SetLevel(99)

	registerMiddlewares(e)

	// create all repositories
	appRepository := repositories.NewGormApplicationRepository(db)

	organizationRepository := repositories.NewGormOrganizationRepository(db)
	patRepository := repositories.NewGormPatRepository(db)
	projectRepository := repositories.NewGormProjectRepository(db)
	envRepository := repositories.NewGormEnvRepository(db)

	// create all controllers
	organizationController := controller.NewOrganizationController(organizationRepository, casbinRBACProvider)

	patController := controller.NewPatController(patRepository)
	projectController := controller.NewProjectController(projectRepository, appRepository)
	applicationController := controller.NewApplicationController(appRepository, envRepository)

	apiV1Router := e.Group("/api/v1")
	// apply the health route without any session or multi tenant middleware
	apiV1Router.GET("/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	sessionMiddleware := appMiddleware.SessionMiddleware(ory, patRepository)

	apiV1Router.GET("/whoami", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"userId": controller.GetSession(c).GetUserID(),
		})
	}, sessionMiddleware)

	patRouter := apiV1Router.Group("/pat")

	patRouter.POST("/", patController.Create, sessionMiddleware)
	patRouter.GET("/", patController.List, sessionMiddleware)
	patRouter.DELETE("/:tokenId", patController.Delete, sessionMiddleware)
	// use the organization router for creating a new organization - this is not multi tenant
	apiV1Router.POST("/organizations", organizationController.Create, sessionMiddleware)
	apiV1Router.GET("/organizations", organizationController.List, sessionMiddleware)

	tenantRouter := e.Group("/api/v1/organizations/:tenant", sessionMiddleware, appMiddleware.MultiTenantMiddleware(casbinRBACProvider, organizationRepository))

	tenantRouter.DELETE("/", organizationController.Delete, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", organizationController.Read, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionRead))
	tenantRouter.GET("/projects", projectController.List, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	tenantRouter.POST("/projects", projectController.Create, appMiddleware.AccessControlMiddleware("organization", accesscontrol.ActionUpdate))

	projectRouter := tenantRouter.Group("/projects/:projectSlug", appMiddleware.ProjectAccessControl(projectRepository, "project", accesscontrol.ActionRead))

	projectRouter.GET("/", projectController.Read)
	projectRouter.POST("/applications", applicationController.Create, appMiddleware.ProjectAccessControl(projectRepository, accesscontrol.ObjectApplication, accesscontrol.ActionCreate))

	applicationRouter := projectRouter.Group("/applications/:applicationSlug")
	applicationRouter.GET("/", applicationController.Read, appMiddleware.ProjectAccessControl(projectRepository, "application", accesscontrol.ActionRead))

	slog.Error("failed to start server", "err", e.Start(":8080").Error())
}
