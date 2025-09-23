package models

import (
	"time"
)

type CWE struct {
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	CWE string `json:"cwe" gorm:"primaryKey;not null;"`

	Description string `json:"description" gorm:"type:text;"`
}

func (m CWE) TableName() string {
	return "cwes"
}
