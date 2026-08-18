package models

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

// scopeRegex matches a CEL expression that's either just a CVE check
// (vuln.cveId == "DEBIAN-CVE-2019-1010022") or one AND-ed with more conditions
// (vuln.cveId == "CVE-2025-61725" && matchesPattern(...)) - the quoted value is
// extracted and stored in CVEScope for SQL-level filtering. Anchored to `&&` or
// end-of-string specifically so "vuln.cveId == \"X\" || ..." is never treated
// as scoped to X - the || means the rule can still match a different CVE.
var scopeRegex = regexp.MustCompile(`^vuln\.cveId\s*==\s*"([^"]+)"\s*(&&.*)?$`)

// ExtractCVEScopeFromCELExpression is used by SetCELExpression/EnsureID below
// so every rule gets a CVEScope the moment its CEL expression is set, rather
// than depending on every call site remembering to compute it separately.
func ExtractCVEScopeFromCELExpression(expr string) *string {
	if !strings.Contains(expr, "vuln.cveId") {
		return nil
	}
	matches := scopeRegex.FindStringSubmatch(expr)
	if len(matches) < 2 {
		return nil
	}
	cveID := matches[1]
	return &cveID
}

type UpstreamVEXRule struct {
	// Single primary key - hash of composite components
	ID string `json:"id" gorm:"primaryKey;not null;"`

	VexSource string `json:"vexSource" gorm:"type:text;not null;index:,composite:vex_composite_key"`

	// Rule data
	Title                   string                           `json:"title" gorm:"type:text;not null"`
	Justification           string                           `json:"justification" gorm:"type:text;not null"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	EventType               dtos.VulnEventType               `json:"eventType" gorm:"type:text;not null;"`

	CELExpression string `json:"celExpression" gorm:"type:text;"`

	CVEScope *string `json:"cveScope" gorm:"type:text;index"` // optional CVE scope for filtering

	CreatedAt time.Time `json:"createdAt" gorm:"not null;default:now();"`
}

func (UpstreamVEXRule) TableName() string {
	return "upstream_vex_rules"
}

// CalculateID computes a SHA256 hash of AssetID, CVEID, PathPattern, CELExpression, and VexSource
// for use as the primary key. This ensures a deterministic, unique ID for each VEX rule combination.
func CalculateVEXRuleID(assetID uuid.UUID, celExpression string, vexSource string) string {
	data := fmt.Sprintf("%s/%s/%s", assetID.String(), celExpression, vexSource)
	return utils.HashString(data)
}

// CalculateUpstreamVEXRuleID hashes the CEL expression, vex source, and rule content
// (title/justification/mechanical_justification/event_type) together, so a content change
// upstream always produces a new id - insert/delete sync then replaces the row naturally,
// without needing a separate content-hash column to detect the change.
func CalculateUpstreamVEXRuleID(celExpression, vexSource, title, justification string, mechanicalJustification dtos.MechanicalJustificationType, eventType dtos.VulnEventType) string {
	data := fmt.Sprintf("%s/%s/%s/%s/%s/%s", celExpression, vexSource, title, justification, mechanicalJustification, eventType)
	return utils.HashString(data)
}

// SetCELExpression sets the CELExpression, recalculates the ID, and re-derives CVEScope.
func (r *UpstreamVEXRule) SetCELExpression(expression string) {
	r.CELExpression = expression
	r.ID = CalculateUpstreamVEXRuleID(r.CELExpression, r.VexSource, r.Title, r.Justification, r.MechanicalJustification, r.EventType)
	r.CVEScope = ExtractCVEScopeFromCELExpression(r.CELExpression)
}

// EnsureID calculates the ID if it hasn't been set yet, and CVEScope from CELExpression.
func (r *UpstreamVEXRule) EnsureID() {
	r.ID = CalculateUpstreamVEXRuleID(r.CELExpression, r.VexSource, r.Title, r.Justification, r.MechanicalJustification, r.EventType)
	r.CVEScope = ExtractCVEScopeFromCELExpression(r.CELExpression)
}
