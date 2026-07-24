package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

type SystemVEXRule struct {
	// Single primary key - hash of composite components
	ID string `json:"id" gorm:"primaryKey;not null;"`

	// Composite key components (for indexing and queries)
	CVEID     string `json:"cveId" gorm:"type:text;not null;index:,composite:vex_composite_key"`
	VexSource string `json:"vexSource" gorm:"type:text;not null;index:,composite:vex_composite_key"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Relationships#
	CVE *CVE `json:"cve" gorm:"foreignKey:CVEID;references:CVE;"`

	// Rule data
	Justification           string                           `json:"justification" gorm:"type:text;not null"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	EventType               dtos.VulnEventType               `json:"eventType" gorm:"type:text;not null;"`

	// PathPattern stores the path patterns for this VEX rule.
	// Supports wildcards: "*" matches any element.
	PathPattern []string `json:"pathPattern" gorm:"type:jsonb;not null;serializer:json"`
	CreatedByID string   `json:"createdById" gorm:"type:text;not null"`
}

// CalculateID computes a SHA256 hash of CVEID, PathPattern, and VexSource for use as the primary key.
// This ensures a deterministic, unique ID for each VEX rule combination.
func CalculateSystemVEXRuleID(cveID string, pathPattern []string, vexSource string) string {
	data := fmt.Sprintf("%s/%s/%s", cveID, strings.Join(pathPattern, ","), vexSource)
	return utils.HashString(data)
}

// SetPathPattern sets the PathPattern and recalculates the ID.
func (r *SystemVEXRule) SetPathPattern(pattern []string) {
	r.PathPattern = pattern
	r.ID = CalculateSystemVEXRuleID(r.CVEID, pattern, r.VexSource)
}

// EnsureID calculates the ID if it hasn't been set yet.
func (r *SystemVEXRule) EnsureID() {
	if r.ID == "" {
		r.ID = CalculateSystemVEXRuleID(r.CVEID, r.PathPattern, r.VexSource)
	}
}
