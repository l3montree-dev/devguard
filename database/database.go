package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
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

// getDSN builds a PostgreSQL connection string from parameters
func getDSN(host, user, password, dbname, port string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)
}

func NewPgxConnPool(cfg PoolConfig) *pgxpool.Pool {
	// create a connection pool with increased connections for parallel processing
	config, err := pgxpool.ParseConfig(getDSN(cfg.Host, cfg.User, cfg.Password, cfg.DBName, cfg.Port))
	if err != nil {
		panic("could not parse pgx pool config")
	}
	config.MaxConnIdleTime = cfg.ConnMaxIdleTime
	config.MaxConnLifetime = cfg.ConnMaxLifetime
	config.MaxConns = cfg.MaxOpenConns
	config.MinConns = cfg.MinConns

	ctx := context.Background()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		panic(fmt.Sprintf("could not create pgx pool: %s", err))
	}

	slog.Info("Database connection pool configured",
		"maxOpenConns", cfg.MaxOpenConns,
		"connMaxLifetime", cfg.ConnMaxLifetime,
		"connMaxIdleTime", cfg.ConnMaxIdleTime,
	)

	return pool
}

// NewGormDB creates a GORM instance using an existing *pgxpool.Pool
func NewGormDB(existingPool *pgxpool.Pool) *gorm.DB {
	// Use the existing connection pool with GORM
	db := stdlib.OpenDBFromPool(existingPool)
	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{
		Logger: &sentryLogger{
			defaultLogger: logger.Default,
		},
	})

	if err != nil {
		panic(err)
	}

	return gormDB
}

func IsDuplicateKeyError(err error) bool {
	return strings.HasPrefix(err.Error(), "ERROR: duplicate key value violates unique constraint")
}
