package main

import (
	"io"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
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
