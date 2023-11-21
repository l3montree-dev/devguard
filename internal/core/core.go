package core

import (
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type Server = *echo.Group
type Context = echo.Context
type DB = *gorm.DB
