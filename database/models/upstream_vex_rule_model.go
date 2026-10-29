package models

import (
	"fmt"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
)

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

// CalculateUpstreamVEXRuleID hashes the CEL expression, vex source, and rule content
// (title/justification/mechanical_justification/event_type) together, so a content change
// upstream always produces a new id - insert/delete sync then replaces the row naturally,
// without needing a separate content-hash column to detect the change.
func CalculateUpstreamVEXRuleID(celExpression, vexSource, title, justification string, mechanicalJustification dtos.MechanicalJustificationType, eventType dtos.VulnEventType) string {
	data := fmt.Sprintf("%s/%s/%s/%s/%s/%s", celExpression, vexSource, title, justification, mechanicalJustification, eventType)
	return utils.HashString(data)
}

// EnsureID recalculates the ID from the rule content.
func (r *UpstreamVEXRule) EnsureID() {
	r.ID = CalculateUpstreamVEXRuleID(r.CELExpression, r.VexSource, r.Title, r.Justification, r.MechanicalJustification, r.EventType)
}

func (r *UpstreamVEXRule) SetCVEScopeFromCELExpression() {
	r.CVEScope = normalize.CVEScopeOfCELExpression(r.CELExpression)
}
