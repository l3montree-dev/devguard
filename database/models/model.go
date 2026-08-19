package models

import (
	"time"

	"github.com/google/uuid"
)

type Model struct {
	ID        uuid.UUID `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (a Model) GetID() uuid.UUID {
	return a.ID
}

func sameExternalEntityOrID(
	id, otherID uuid.UUID,
	externalID, otherExternalID,
	providerID, otherProviderID *string,
) bool {
	if externalID != nil && providerID != nil && otherExternalID != nil && otherProviderID != nil {
		return *externalID == *otherExternalID && *providerID == *otherProviderID
	}
	return id != uuid.Nil && id == otherID
}
