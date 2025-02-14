package models

import (
	"github.com/google/uuid"
)

type Comment struct {
	Model
	VulnID  uuid.UUID `json:"vulnId"`
	UserID  uuid.UUID `json:"userId"`
	Comment string    `json:"comment"`
}

func (m Comment) TableName() string {
	return "comments"
}
