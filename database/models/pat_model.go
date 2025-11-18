package models

import (
	"crypto/sha256"
	"encoding/base64"
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
