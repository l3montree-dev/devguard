package pat

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

type Model struct {
	CreatedAt   time.Time `json:"createdAt"`
	UserID      uuid.UUID `json:"userId"`
	Token       string    `json:"-"`
	Description string    `json:"description" gorm:"type:text"`
	ID          uuid.UUID `json:"id" gorm:"type:uuid;default:gen_random_uuid()"`
}

func (p Model) TableName() string {
	return "pat"
}

func (p Model) HashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	// make it base64
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func (p Model) GetUserID() string {
	return p.UserID.String()
}
