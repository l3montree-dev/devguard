package mitigation

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"

	"gorm.io/datatypes"
)

type (
	Type string
)

const (
	TypeAvoid    Type = "avoid"
	TypeAccept   Type = "accept"
	TypeFix      Type = "fix"
	TypeTransfer Type = "transfer"
)

type Mitigation struct {
	core.Model
	Type             Type      `json:"mitigationType"`
	InitiatingUserID string    `json:"initiatingUserId"`
	ResultID         uuid.UUID `json:"resultId"`

	DueDate    *time.Time     `json:"dueDate"`
	Properties datatypes.JSON `gorm:"type:jsonb;default:'{}';not null"`

	MitigationPending bool   `json:"mitigationPending" gorm:"default:false"` // will be true for fix and transfer types - we are waiting for another scan report which verifies, that the related result is fixed. Will be false for avoid and accept types
	Justification     string `json:"justification"`
}
