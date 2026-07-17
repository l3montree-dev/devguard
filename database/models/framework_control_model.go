package models

import (
	"fmt"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type FrameworkControl struct {
	FrameworkControlID string `json:"frameworkControlId" gorm:"type:text;primaryKey;"`
	Title              string `json:"title"`
	Class              string `json:"class"`
	Description        string `json:"description"`

	Importance string `json:"importance"`

	Framework string `yaml:"framework" json:"framework"`
	ControlID string `yaml:"controls"  json:"controls" gorm:"column:control_id;type:text;index"`

	Additional datatypes.JSON `yaml:"additional" json:"additional" gorm:"type:jsonb"`

	ParentFrameworkControlID *string `json:"parentFrameworkControlId" gorm:"type:text;index"`

	MappedControls []MappedControl `json:"mappedControls" gorm:"foreignKey:FrameworkControlID;references:FrameworkControlID;constraint:OnDelete:CASCADE;"`
}

type MappedControl struct {
	FrameworkControlID string `json:"frameworkControlId" gorm:"type:text;primaryKey;"`

	RelatedFramework string `json:"relatedFramework" gorm:"type:text;primaryKey;"`
	RelatedControlID string `json:"relatedControlId" gorm:"type:text;primaryKey;"`

	FrameworkControl FrameworkControl `gorm:"foreignKey:FrameworkControlID;references:FrameworkControlID;constraint:OnDelete:CASCADE;"`
}

func (m FrameworkControl) TableName() string {
	return "frameworks_controls"
}

func (m *FrameworkControl) SetID() {
	m.FrameworkControlID = fmt.Sprintf("%s:%s", m.Framework, m.ControlID)
}

func (m *FrameworkControl) BeforeSave(tx *gorm.DB) (err error) {
	m.SetID()
	return nil
}
