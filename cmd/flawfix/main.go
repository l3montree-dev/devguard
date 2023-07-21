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
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/l3montree-dev/flawfix/models"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/owenrumney/go-sarif/sarif"

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

func getCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func sessionMiddleware(oryApiClient *client.APIClient) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {

			oryKratosSessionCookie := getCookie("ory_kratos_session", c.Cookies())
			if oryKratosSessionCookie == nil {
				return c.JSON(401, map[string]string{"error": "no session cookie"})
			}

			// check if we have a session
			session, _, err := oryApiClient.FrontendApi.ToSession(c.Request().Context()).Cookie(oryKratosSessionCookie.String()).Execute()
			if (err != nil && session == nil) || (err == nil && !*session.Active) {
				return c.JSON(401, map[string]string{"error": "no session"})
			}

			c.Set("session", session)
			c.Set("sessionCookie", oryKratosSessionCookie)
			// continue to the requested page (in our case the Dashboard)
			return next(c)
		}
	}
}

func getSession(ctx echo.Context) *client.Session {
	session := ctx.Get("session").(*client.Session)
	return session
}

func main() {
	godotenv.Load()

	ory := getOryApiClient()

	db, err := models.NewConnection(os.Getenv("POSTGRES_HOST"), "5432", os.Getenv("POSTGRES_DB"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"))
	if err != nil {
		panic(err)
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	appRepository := models.NewApplicationRepository(db)
	sarifWrapper := models.NewSarifWrapper(db, appRepository)

	e.GET("/api/v1/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	authorizedGroup := e.Group("/api/v1", sessionMiddleware(ory))

	authorizedGroup.GET("/", func(c echo.Context) error {
		return c.JSON(200, getSession(c))
	})

	authorizedGroup.POST("/reports", func(c echo.Context) error {
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
		err = sarifWrapper.SaveSarifReport("test", report)

		if err != nil {
			return err
		}

		return c.String(200, "ok")
	})

	e.Logger.Fatal(e.Start(":8080"))
}
