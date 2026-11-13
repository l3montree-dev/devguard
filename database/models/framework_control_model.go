package models

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/datatypes"
)

// FrameworkControl is identified by the hash of its resolved content.
// The same control can belong to several frameworks via ScopeFramework.
type FrameworkControl struct {
	ControlHash string `json:"controlHash" gorm:"type:text;primaryKey;"`
	Title       string `json:"title"`
	Class       string `json:"class"`
	Description string `json:"description"`

	Importance    string `json:"importance"`
	SecurityLevel string `json:"securityLevel"`

	ControlID string `yaml:"controls"  json:"controls" gorm:"column:control_id;type:text;index"`

	Additional datatypes.JSON `yaml:"additional" json:"additional" gorm:"type:jsonb"`

	ParentControlID *string `json:"parentControlId" gorm:"type:text;index;column:parent_control_id"`

	ScopeFrameworks []ScopeFramework `json:"scopeFrameworks,omitempty" gorm:"many2many:scope_framework_controls;foreignKey:ControlHash;joinForeignKey:ControlHash;references:ID;joinReferences:ScopeFrameworkID"`
}

// MappedControl references a control by "<framework>:<control_id>".
type MappedControl struct {
	FrameworkControlID string `json:"frameworkControlId" gorm:"type:text;primaryKey;"`

	RelatedFramework string `json:"relatedFramework" gorm:"type:text;primaryKey;"`
	RelatedControlID string `json:"relatedControlId" gorm:"type:text;primaryKey;"`

	Relationship string `json:"relationship" gorm:"type:text;primaryKey;default:''"`
}

func (m FrameworkControl) TableName() string {
	return "compliance_controls"
}

func (m FrameworkControl) CalculateHash() string {
	return utils.HashString(fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", m.ControlID, m.Title, m.Class, m.Description, m.Importance, m.SecurityLevel, utils.SafeDereference(m.ParentControlID)))
}

// ScopeFramework is a framework (catalog) activated or uploaded in an org, project or asset.
type ScopeFramework struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Framework string     `json:"framework" gorm:"type:text;not null"`
	OrgID     uuid.UUID  `json:"orgId" gorm:"type:uuid;not null;column:org_id"`
	ProjectID *uuid.UUID `json:"projectId" gorm:"type:uuid;column:project_id"`
	AssetID   *uuid.UUID `json:"assetId" gorm:"type:uuid;column:asset_id"`

	Controls []FrameworkControl `json:"controls" gorm:"many2many:scope_framework_controls;foreignKey:ID;joinForeignKey:ScopeFrameworkID;references:ControlHash;joinReferences:ControlHash"`
}

func (m ScopeFramework) TableName() string {
	return "scope_frameworks"
}
