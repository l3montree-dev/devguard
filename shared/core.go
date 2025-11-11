package shared

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
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
	db, err := database.NewConnection(os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"), os.Getenv("POSTGRES_PORT"))

	return db, err
}

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func InitLogger() {
	// slog.HandlerOptions
	w := os.Stderr

	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      slog.LevelDebug,
			AddSource:  true,
			TimeFormat: time.Kitchen,
		}),
	))
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

func BootstrapOrg(rbac AccessControl, userID string, userRole Role) error {
	if err := rbac.GrantRole(userID, userRole); err != nil {
		return err
	}

	if err := rbac.InheritRole(RoleOwner, RoleAdmin); err != nil { // an owner is an admin
		return err
	}
	if err := rbac.InheritRole(RoleAdmin, RoleMember); err != nil { // an admin is a member
		return err
	}

	if err := rbac.AllowRole(RoleOwner, ObjectOrganization, []Action{
		ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole(RoleAdmin, ObjectOrganization, []Action{
		ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole(RoleAdmin, ObjectProject, []Action{
		ActionCreate,
		ActionRead, // listing all projects
		ActionUpdate,
		ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole(RoleMember, ObjectOrganization, []Action{
		ActionRead,
	}); err != nil {
		return err
	}

	return nil
}
