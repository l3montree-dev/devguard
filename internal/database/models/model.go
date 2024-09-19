package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type Model struct {
	ID        uuid.UUID    `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	DeletedAt sql.NullTime `gorm:"index" json:"-"`
}

func (a Model) GetID() uuid.UUID {
	return a.ID
}
