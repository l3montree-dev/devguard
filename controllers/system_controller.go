// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package controllers

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/config"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

type SystemController struct {
	db     shared.DB
	pool   *pgxpool.Pool
	broker shared.PubSubBroker

	healthConn   *pgxpool.Conn
	healthConnMu sync.Mutex
}

func NewSystemController(db shared.DB, pool *pgxpool.Pool, broker shared.PubSubBroker) *SystemController {
	if pool == nil {
		panic("NewSystemController: pool must not be nil")
	}

	s := &SystemController{db: db, pool: pool, broker: broker}

	initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.pingDedicatedHealthConn(initCtx); err != nil {
		panic("NewSystemController: could not initialize dedicated health-check connection: " + err.Error())
	}

	return s
}

// The connection is reserved once and reused so that health checks aren't
// subject to the same pool contention they're meant to detect.
func (s *SystemController) pingDedicatedHealthConn(ctx context.Context) error {
	s.healthConnMu.Lock()
	defer s.healthConnMu.Unlock()

	if s.healthConn == nil {
		conn, err := s.pool.Acquire(ctx)
		if err != nil {
			return err
		}
		s.healthConn = conn
		slog.Info("reserved dedicated health-check database connection")
	}

	if err := s.healthConn.Ping(ctx); err != nil {
		if ctx.Err() == nil {
			s.healthConn.Release()
			s.healthConn = nil
		}
		return err
	}

	return nil
}

// @Summary Runtime, build and database diagnostics
// @Tags System
// @Success 200 {object} dtos.InfoResponse
// @Router /info [get]
func (s *SystemController) Info(c shared.Context) error {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	resp := dtos.InfoResponse{
		Build: dtos.BuildInfo{
			Version:   config.Version,
			Commit:    config.Commit,
			Branch:    config.Branch,
			BuildDate: config.BuildDate,
		},
		Runtime: dtos.RuntimeInfo{
			GoVersion:     runtime.Version(),
			NumGoroutines: runtime.NumGoroutine(),
			Mem: dtos.MemStats{
				Alloc:      mem.Alloc,
				TotalAlloc: mem.TotalAlloc,
				Sys:        mem.Sys,
				HeapAlloc:  mem.HeapAlloc,
			},
		},
		Process: dtos.ProcessInfo{
			PID:           os.Getpid(),
			UptimeSeconds: int(time.Since(api.StartedAt).Seconds()),
		},
	}

	host, _ := os.Hostname()
	if host != "" {
		resp.Process.Hostname = host
	}

	poolCfg := database.GetPoolConfigFromEnv()
	poolInfo := dtos.PoolInfo{
		DBName:          poolCfg.DBName,
		MaxOpenConns:    poolCfg.MaxOpenConns,
		ConnMaxLifetime: poolCfg.ConnMaxLifetime.String(),
		ConnMaxIdleTime: poolCfg.ConnMaxIdleTime.String(),
	}

	dbInfo := dtos.DatabaseInfo{Status: "unknown"}
	sqlDB, err := s.db.DB()
	if err != nil {
		errMsg := "failed to get database instance"
		dbInfo.Status = "unhealthy"
		dbInfo.Error = &errMsg
	} else if err := sqlDB.Ping(); err != nil {
		errMsg := "database ping failed"
		dbInfo.Status = "unhealthy"
		dbInfo.Error = &errMsg
	} else {
		dbInfo.Status = "healthy"

		stats := s.pool.Stat()
		dbInfo.OpenConnections = int(stats.TotalConns())
		dbInfo.InUse = int(stats.AcquiredConns())
		dbInfo.Idle = int(stats.IdleConns())
		dbInfo.MaxOpenConnections = int(stats.MaxConns())

		poolInfo.TotalConns = int(stats.TotalConns())
		poolInfo.IdleConns = int(stats.IdleConns())
		poolInfo.AcquiredConns = int(stats.AcquiredConns())
		poolInfo.MaxConns = int(stats.MaxConns())

		if ver, dirty, err := database.GetMigrationVersionFromDB(s.db); err == nil {
			v := ver
			dbInfo.MigrationVersion = &v
			dbInfo.MigrationDirty = &dirty
		} else {
			errStr := err.Error()
			dbInfo.MigrationError = &errStr
		}

		var cfg models.Config
		if err := s.db.Where("key = ?", "vulndb.lastRCImport").First(&cfg).Error; err == nil {
			var last string
			if err := json.Unmarshal([]byte(cfg.Val), &last); err == nil {
				dbInfo.VulnDBVersion = &last
			} else {
				copy := cfg.Val
				dbInfo.VulnDBVersion = &copy
			}
		}
	}
	resp.Database.Pool = &poolInfo
	resp.Database = dbInfo

	return c.JSON(200, resp)
}

// @Summary Liveness and readiness check
// @Tags System
// @Success 200 {object} object{status=string}
// @Failure 503 {object} object{status=string,error=string}
// @Router /health [get]
func (s *SystemController) Health(c shared.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		slog.Info("failed to get database instance", "error", err)
		return c.JSON(503, map[string]string{
			"status": "unhealthy",
			"error":  "failed to get database instance",
		})
	}

	ctxWithTimeout, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	pingStart := time.Now()

	pingErr := s.pingDedicatedHealthConn(ctxWithTimeout)

	if pingErr != nil {
		sqlStats := sqlDB.Stats()
		logArgs := []any{
			"error", pingErr,
			"usingDedicatedHealthConn", true,
			"pingDuration", time.Since(pingStart),
			"requestContextErr", c.Request().Context().Err(),
			"pingContextErr", ctxWithTimeout.Err(),
			"sqlOpenConnections", sqlStats.OpenConnections,
			"sqlInUse", sqlStats.InUse,
			"sqlIdle", sqlStats.Idle,
			"sqlWaitCount", sqlStats.WaitCount,
			"sqlWaitDuration", sqlStats.WaitDuration,
		}

		pgxStats := s.pool.Stat()
		logArgs = append(logArgs,
			"pgxTotalConns", pgxStats.TotalConns(),
			"pgxAcquiredConns", pgxStats.AcquiredConns(),
			"pgxIdleConns", pgxStats.IdleConns(),
			"pgxMaxConns", pgxStats.MaxConns(),
			"pgxAcquireCount", pgxStats.AcquireCount(),
			"pgxAcquireDuration", pgxStats.AcquireDuration(),
		)

		slog.Info("database ping failed", logArgs...)
		return c.JSON(503, map[string]string{
			"status": "unhealthy",
			"error":  "database ping failed",
		})
	}

	if !s.broker.IsHealthy() {
		slog.Info("database pub/sub connection is unhealthy")
		return c.JSON(503, map[string]string{
			"status": "unhealthy",
			"error":  "database pub/sub connection failed",
		})
	}

	return c.JSON(200, map[string]string{
		"status": "healthy",
	})
}
