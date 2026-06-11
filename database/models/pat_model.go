package models

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

// PAT represents a personal access token. Two mutually exclusive auth modes:
//   - Asymmetric (ECDSA request signing): PubKey and Fingerprint are set; BearerTokenHash is empty.
//   - Symmetric (Bearer token): BearerTokenHash is set; PubKey and Fingerprint are empty.
type PAT struct {
	CreatedAt       time.Time  `json:"createdAt"`
	UserID          uuid.UUID  `json:"userId"`
	PubKey          *string    `json:"pubKey"`
	Description     string     `json:"description" gorm:"type:text"`
	ID              uuid.UUID  `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	Fingerprint     *string    `json:"fingerprint"`
	BearerTokenHash *string    `json:"-" gorm:"type:text"` // never expose the hash to clients
	LastUsedAt      *time.Time `json:"lastUsedAt" gorm:"default:null"`
	Scopes          string     `json:"scopes" gorm:"type:text"`
}

func (p PAT) TableName() string {
	return "pat"
}

func (p PAT) IsSymmetricSecret() bool {
	return p.BearerTokenHash != nil && *p.BearerTokenHash != ""
}

func (p PAT) IsAsymmetricSecret() bool {
	return p.Fingerprint != nil && *p.Fingerprint != ""
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
