package models

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PAT struct {
	CreatedAt   time.Time `json:"createdAt"`
	UserID      uuid.UUID `json:"userId"`
	PubKey      string    `json:"pubKey"`
	Description string    `json:"description" gorm:"type:text"`
	ID          uuid.UUID `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	Fingerprint string    `json:"fingerprint"`

	DeletedAt gorm.DeletedAt `json:"deletedAt"`
}

func (p PAT) TableName() string {
	return "pat"
}

func (p PAT) HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	// make it base64
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func (p PAT) GetUserID() string {
	return p.UserID.String()
}
