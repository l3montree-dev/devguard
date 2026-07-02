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

	Framework string `yaml:"framework" json:"framework"`
	ControlID string `yaml:"controls"  json:"controls"`

	Additional datatypes.JSON `yaml:"additional" json:"additional" gorm:"type:jsonb"`

	ParentFrameworkControlID *string `json:"parentFrameworkControlId" gorm:"type:text;index"`
}

func (m FrameworkControl) TableName() string {
	return "frameworks_controls"
}

func (m *FrameworkControl) SetID() {
	m.FrameworkControlID = fmt.Sprintf("%s:%s", m.Framework, m.ControlID)
}

func (m *FrameworkControl) BeforeSave(tx *gorm.DB) (err error) {
	if m.FrameworkControlID == "" {
		m.SetID()
	}
	return nil
}
