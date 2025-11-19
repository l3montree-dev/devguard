package models

import (
	"github.com/google/uuid"
)

type Comment struct {
	Model
	DependencyVulnID uuid.UUID `json:"dependencyVulnId"`
	UserID           uuid.UUID `json:"userId"`
	Comment          string    `json:"comment"`
}

func (m Comment) TableName() string {
	return "comments"
}
