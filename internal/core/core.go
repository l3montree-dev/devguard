package core

import (
	"log/slog"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/golang-cz/devslog"
	"github.com/joho/godotenv"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
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
	// slog.HandlerOptions
	slogOpts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}

	// new logger with options
	opts := &devslog.Options{
		HandlerOptions:    slogOpts,
		MaxSlicePrintSize: 4,
		SortKeys:          true,
		NewLineAfterLog:   true,
		StringerFormatter: true,
	}

	logger := slog.New(devslog.NewHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}

func LoadConfig() error {
	return godotenv.Load()
}

var V = validator.New()

func GetEnvironmentalFromAsset(m models.Asset) Environmental {
	return SanitizeEnv(Environmental{
		ConfidentialityRequirements: string(m.ConfidentialityRequirement),
		AvailabilityRequirements:    string(m.AvailabilityRequirement),
		IntegrityRequirements:       string(m.IntegrityRequirement),
	})
}
