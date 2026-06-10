package models

import (
	"time"

	"github.com/google/uuid"
)

type PAT struct {
	CreatedAt   time.Time  `json:"createdAt"`
	UserID      uuid.UUID  `json:"userId"`
	PubKey      string     `json:"pubKey"`
	Description string     `json:"description" gorm:"type:text"`
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	Fingerprint string     `json:"fingerprint"`
	LastUsedAt  *time.Time `json:"lastUsedAt" gorm:"default:null"`
	Scopes      string     `json:"scopes" gorm:"type:text"` // whitespace separated scopes manage-project read-project scan-asset manage-all
	ExpiryDate  *time.Time `json:"expiryDate"`
}

func (p PAT) TableName() string {
	return "pat"
}

func (p PAT) GetUserID() string {
	return p.UserID.String()
}
