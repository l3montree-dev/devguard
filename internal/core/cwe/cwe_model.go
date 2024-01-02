package cwe

import (
	"database/sql"
	"time"
)

type CWEModel struct {
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`

	CWE  string      `json:"cwe" gorm:"primaryKey;not null;"`
	CVEs []*CVEModel `json:"cve" gorm:"many2many:cve_cwe;"`

	Description string `json:"description" gorm:"type:text;"`
}

func (m CWEModel) TableName() string {
	return "cwes"
}
