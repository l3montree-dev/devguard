package core

import (
	"log/slog"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/labstack/echo/v4"
	"github.com/lmittmann/tint"
	"gorm.io/gorm"
)

type Server = *echo.Group
type MiddlewareFunc = echo.MiddlewareFunc
type Context = echo.Context
type DB = *gorm.DB

func Ptr[T any](t T) *T {
	return &t
}

func SanitizeParam(s string) string {
	// remove trailing or leading slashes
	return strings.Trim(s, "/")
}

func DatabaseFactory() (DB, error) {
	db, err := database.NewConnection(os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"), "5432")

	return db, err
}

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func InitLogger() {
	loggingHandler := tint.NewHandler(os.Stdout, &tint.Options{
		AddSource: true,
		Level:     slog.LevelDebug,
	})
	logger := slog.New(loggingHandler)
	slog.SetDefault(logger)
}

func LoadConfig() error {
	return godotenv.Load()
}

var V = validator.New()
