package core

import (
	"strings"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type Server = *echo.Group
type Context = echo.Context
type DB = *gorm.DB

func SanitizeParam(s string) string {
	// remove trailing or leading slashes
	return strings.Trim(s, "/")
}
