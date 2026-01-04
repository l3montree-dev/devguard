package router

import "database/sql"

// InfoResponse is the typed response returned by the /api/v1/info/ endpoint.
// It is structured for readable inspection by humans and machines.
type InfoResponse struct {
	Build    BuildInfo    `json:"build"`
	Process  ProcessInfo  `json:"process"`
	Runtime  RuntimeInfo  `json:"runtime"`
	Database DatabaseInfo `json:"database"`
}

// BuildInfo holds compiled build metadata
type BuildInfo struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	Branch    string `json:"branch,omitempty"`
	BuildDate string `json:"buildDate,omitempty"`
}

// ProcessInfo holds process-level diagnostics
type ProcessInfo struct {
	PID           int    `json:"pid"`
	Hostname      string `json:"hostname,omitempty"`
	UptimeSeconds int    `json:"uptimeSeconds"`
}

// RuntimeInfo aggregates Go runtime diagnostics
type RuntimeInfo struct {
	GoVersion     string   `json:"goVersion,omitempty"`
	NumGoroutines int      `json:"numGoroutines,omitempty"`
	Mem           MemStats `json:"mem,omitempty"`
}

// MemStats focuses on a small, relevant subset of runtime.MemStats
type MemStats struct {
	Alloc      uint64 `json:"alloc"`
	TotalAlloc uint64 `json:"totalAlloc"`
	Sys        uint64 `json:"sys"`
	HeapAlloc  uint64 `json:"heapAlloc"`
}

// DatabaseInfo describes DB connectivity and migration/vulndb metadata
type DatabaseInfo struct {
	sql.DBStats
	Status string  `json:"status"`
	Error  *string `json:"error,omitempty"`

	MigrationVersion *uint   `json:"migrationVersion,omitempty"`
	MigrationDirty   *bool   `json:"migrationDirty,omitempty"`
	MigrationError   *string `json:"migrationError,omitempty"`

	VulnDBVersion *string `json:"vulndbVersion,omitempty"`
}
