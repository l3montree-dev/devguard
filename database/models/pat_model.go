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
	UserID          *uuid.UUID `json:"userId"`
	OrgID           *uuid.UUID `json:"orgID" gorm:"column:org_id"`
	ProjectID       *uuid.UUID `json:"projectID"`
	AssetID         *uuid.UUID `json:"assetID"`
	PubKey          *string    `json:"pubKey"`
	Description     string     `json:"description" gorm:"type:text"`
	ID              uuid.UUID  `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
	Fingerprint     *string    `json:"fingerprint"`
	BearerTokenHash *string    `json:"-" gorm:"type:text"` // never expose the hash to clients
	LastUsedAt      *time.Time `json:"lastUsedAt" gorm:"default:null"`
	ExpiryDate      *time.Time `json:"expiryDate"`
	Scopes          string     `json:"scopes" gorm:"type:text"`
}

func (p PAT) TableName() string {
	return "access_tokens"
}

func (p PAT) OwnerType() string {
	switch {
	case p.UserID != nil:
		return "user"
	case p.OrgID != nil:
		return "org"
	case p.ProjectID != nil:
		return "project"
	case p.AssetID != nil:
		return "asset"
	default:
		return ""
	}
}

func (p PAT) IsSymmetricSecret() bool {
	return p.BearerTokenHash != nil && *p.BearerTokenHash != ""
}

func (p PAT) IsAsymmetricSecret() bool {
	return p.Fingerprint != nil && *p.Fingerprint != ""
}

func (p PAT) IsExpired() bool {
	return p.ExpiryDate != nil && p.ExpiryDate.Before(time.Now())
}

func (p PAT) HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func (p PAT) GetUserID() string {
	if p.UserID == nil {
		return ""
	}
	return p.UserID.String()
}

func (p PAT) GetOrgID() string {
	if p.OrgID == nil {
		return ""
	}
	return p.OrgID.String()
}

func (p PAT) GetProjectID() string {
	if p.ProjectID == nil {
		return ""
	}
	return p.ProjectID.String()
}

func (p PAT) GetAssetID() string {
	if p.AssetID == nil {
		return ""
	}
	return p.AssetID.String()
}
