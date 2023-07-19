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

	"github.com/joho/godotenv"
	"github.com/l3montree-dev/flawfix/db"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	godotenv.Load()

	_, err := db.NewConnection(os.Getenv("POSTGRES_HOST"), "5432", os.Getenv("POSTGRES_DB"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"))
	if err != nil {
		panic(err)
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.GET("/health", func(c echo.Context) error {
		return c.String(200, "ok")
	})

	e.POST("/reports", func(c echo.Context) error {
		// print the request body as string
		reportStr, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		println(string(reportStr))
		return c.String(200, "ok")
	})

	e.Logger.Fatal(e.Start(":8080"))
}
