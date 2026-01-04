// Copyright (C) 2025 l3montree GmbH
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

package database

import (
	"os"
	"strconv"
	"time"
)

// PoolConfig holds database connection pool configuration
// This is used by both GORM and pgx pools to ensure consistent connection management
type PoolConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	DBName   string

	MaxOpenConns    int32
	MinConns        int32
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// GetPoolConfigFromEnv reads pool configuration from environment variables
// Falls back to sensible defaults if not specified
//
// Environment variables:
// - DB_MAX_OPEN_CONNS: Maximum number of open connections (default: 25)
// - DB_MAX_IDLE_CONNS: Maximum number of idle connections (default: 5)
// - DB_CONN_MAX_LIFETIME: Maximum connection lifetime, e.g. "5m" (default: 5 minutes)
// - DB_CONN_MAX_IDLE_TIME: Maximum idle time before closing, e.g. "1m" (default: 1 minute)
func GetPoolConfigFromEnv() PoolConfig {
	cfg := PoolConfig{
		MaxOpenConns:    25, // Default: conservative limit
		ConnMaxLifetime: 4 * time.Hour,
		ConnMaxIdleTime: 15 * time.Minute,
		MinConns:        5, // Default: keep some idle connections
		/**
		  POSTGRES_USER=devguard
		  POSTGRES_PASSWORD=devguard
		  POSTGRES_DB=devguard
		  POSTGRES_HOST=localhost
		  POSTGRES_PORT=5432
		*/
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Host:     os.Getenv("POSTGRES_HOST"),
		Port:     os.Getenv("POSTGRES_PORT"),
		DBName:   os.Getenv("POSTGRES_DB"),
	}

	// Allow override via environment variables
	if maxOpen := os.Getenv("DB_MAX_OPEN_CONNS"); maxOpen != "" {
		if val, err := strconv.Atoi(maxOpen); err == nil && val > 0 {
			cfg.MaxOpenConns = int32(val)
		}
	}

	if minConns := os.Getenv("DB_MIN_CONNS"); minConns != "" {
		if val, err := strconv.Atoi(minConns); err == nil && val >= 0 {
			cfg.MinConns = int32(val)
		}
	}

	if lifetime := os.Getenv("DB_CONN_MAX_LIFETIME"); lifetime != "" {
		if val, err := time.ParseDuration(lifetime); err == nil {
			cfg.ConnMaxLifetime = val
		}
	}

	if idleTime := os.Getenv("DB_CONN_MAX_IDLE_TIME"); idleTime != "" {
		if val, err := time.ParseDuration(idleTime); err == nil {
			cfg.ConnMaxIdleTime = val
		}
	}

	return cfg
}
