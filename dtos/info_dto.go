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

package dtos

import (
	"time"
)

type InfoResponse struct {
	Build    BuildInfo    `json:"build"`
	Process  ProcessInfo  `json:"process"`
	Runtime  RuntimeInfo  `json:"runtime"`
	Database DatabaseInfo `json:"database"`
}

type BuildInfo struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Branch    string `json:"branch,omitempty"`
	BuildDate string `json:"buildDate,omitempty"`
}

type ProcessInfo struct {
	PID           int    `json:"pid"`
	Hostname      string `json:"hostname,omitempty"`
	UptimeSeconds int    `json:"uptimeSeconds"`
}

type RuntimeInfo struct {
	GoVersion     string   `json:"goVersion,omitempty"`
	NumGoroutines int      `json:"numGoroutines,omitempty"`
	Mem           MemStats `json:"mem"`
}

type MemStats struct {
	Alloc      uint64 `json:"alloc"`
	TotalAlloc uint64 `json:"totalAlloc"`
	Sys        uint64 `json:"sys"`
	HeapAlloc  uint64 `json:"heapAlloc"`
}

// PoolInfo intentionally omits sensitive fields (e.g. passwords).
type PoolInfo struct {
	DBName          string `json:"dbName,omitempty"`
	MaxOpenConns    int32  `json:"maxOpenConns,omitempty"`
	ConnMaxLifetime string `json:"connMaxLifetime,omitempty"`
	ConnMaxIdleTime string `json:"connMaxIdleTime,omitempty"`

	TotalConns    int `json:"totalConns,omitempty"`
	IdleConns     int `json:"idleConns,omitempty"`
	AcquiredConns int `json:"acquiredConns,omitempty"`
	MaxConns      int `json:"maxConns,omitempty"`
}

type DBStats struct {
	MaxOpenConnections int `json:"maxOpenConnections,omitempty"`

	OpenConnections int `json:"openConnections,omitempty"`
	InUse           int `json:"inUse,omitempty"`
	Idle            int `json:"idle,omitempty"`

	WaitCount         int64         `json:"waitCount,omitempty"`
	WaitDuration      time.Duration `json:"waitDuration,omitempty"`
	MaxIdleClosed     int64         `json:"maxIdleClosed,omitempty"`
	MaxIdleTimeClosed int64         `json:"maxIdleTimeClosed,omitempty"`
	MaxLifetimeClosed int64         `json:"maxLifetimeClosed,omitempty"`
}

type DatabaseInfo struct {
	DBStats
	Status string  `json:"status"`
	Error  *string `json:"error,omitempty"`

	MigrationVersion *uint   `json:"migrationVersion,omitempty"`
	MigrationDirty   *bool   `json:"migrationDirty,omitempty"`
	MigrationError   *string `json:"migrationError,omitempty"`

	VulnDBVersion *string `json:"vulndbVersion,omitempty"`

	Pool *PoolInfo `json:"pool,omitempty"`
}
