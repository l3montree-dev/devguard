package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

type SystemVEXRule struct {
	// Single primary key - hash of composite components
	ID string `json:"id" gorm:"primaryKey;not null;"`

	VexSource string `json:"vexSource" gorm:"type:text;not null;index:,composite:vex_composite_key"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Rule data
	Title                   string                           `json:"title" gorm:"type:text;not null"`
	Justification           string                           `json:"justification" gorm:"type:text;not null"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	EventType               dtos.VulnEventType               `json:"eventType" gorm:"type:text;not null;"`

	CELExpression string `json:"celExpression" gorm:"type:text;"`
}

func (SystemVEXRule) TableName() string {
	return "system_vex_rules"
}

// CalculateID computes a SHA256 hash of AssetID, CVEID, PathPattern, CELExpression, and VexSource
// for use as the primary key. This ensures a deterministic, unique ID for each VEX rule combination.
func CalculateVEXRuleID(assetID uuid.UUID, celExpression string, vexSource string) string {
	data := fmt.Sprintf("%s/%s/%s", assetID.String(), celExpression, vexSource)
	return utils.HashString(data)
}

// SetCELExpression sets the CELExpression and recalculates the ID.
func (r *SystemVEXRule) SetCELExpression(expression string) {
	r.CELExpression = expression
	r.ID = CalculateVEXRuleID(uuid.Nil, r.CELExpression, r.VexSource)
}

// EnsureID calculates the ID if it hasn't been set yet.
func (r *SystemVEXRule) EnsureID() {
	if r.ID == "" {
		r.ID = CalculateVEXRuleID(uuid.Nil, r.CELExpression, r.VexSource)
	}
}
