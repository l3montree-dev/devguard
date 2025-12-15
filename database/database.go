package database

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/monitoring"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// create a logger to log any errors to the error tracking
type sentryLogger struct {
	defaultLogger logger.Interface
}

func (s *sentryLogger) LogMode(level logger.LogLevel) logger.Interface {
	// Return a new sentryLogger wrapping the logger returned by the
	// underlying logger's LogMode. This avoids mutating the original
	// wrapper (which may be used concurrently) and matches GORM's
	// expectation that LogMode returns a logger.Interface configured
	// for the requested level.
	var newDefault logger.Interface
	if s.defaultLogger != nil {
		newDefault = s.defaultLogger.LogMode(level)
	}
	return &sentryLogger{defaultLogger: newDefault}
}
func (s *sentryLogger) Info(ctx context.Context, msg string, data ...any) {
	s.alert(msg, data...)
	s.defaultLogger.Info(ctx, msg, data...)
}
func (s *sentryLogger) Warn(ctx context.Context, msg string, data ...any) {
	s.alert(msg, data...)
	s.defaultLogger.Warn(ctx, msg, data...)
}
func (s *sentryLogger) Error(ctx context.Context, msg string, data ...any) {
	s.alert(msg, data...)
	s.defaultLogger.Error(ctx, msg, data...)
}

func (s *sentryLogger) alert(msg string, data ...any) {
	if len(data) > 0 {
		err, ok := data[0].(error)
		if ok {
			// check if record not found error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return
			}
			monitoring.Alert(msg, err)
		} else {
			monitoring.Alert(msg, fmt.Errorf("%v", data[0]))
		}
	} else {
		monitoring.Alert(msg, nil)
	}
}

func (s *sentryLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if err != nil {
		s.alert("Database error", err)
	}
	s.defaultLogger.Trace(ctx, begin, fc, err)
}

func NewConnection(host, user, password, dbname, port string) (*gorm.DB, error) {
	// https://github.com/go-gorm/postgres
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname),
	}), &gorm.Config{
		Logger: &sentryLogger{
			defaultLogger: logger.Default,
		},
	})

	if err != nil {
		return nil, err
	}

	return db, nil
}

func IsDuplicateKeyError(err error) bool {
	return strings.HasPrefix(err.Error(), "ERROR: duplicate key value violates unique constraint")
}

type PageInfo struct {
	Total    int64 `json:"total"`
	PageSize int   `json:"pageSize"`
	Page     int   `json:"page"`
}

type JSONB map[string]any

// Value Marshal
func (jsonField JSONB) Value() (driver.Value, error) {
	return json.Marshal(jsonField)
}

// Scan Unmarshal
func (jsonField *JSONB) Scan(value any) error {
	data, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(data, &jsonField)
}

func JSONbFromStruct(m any) (JSONB, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var jsonb JSONB
	err = json.Unmarshal(data, &jsonb)
	if err != nil {
		return nil, err
	}
	return jsonb, nil
}

func MustJSONBFromStruct(m any) JSONB {
	jsonb, err := JSONbFromStruct(m)
	if err != nil {
		panic(err)
	}
	return jsonb
}
