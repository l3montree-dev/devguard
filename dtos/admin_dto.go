package dtos

import "github.com/google/uuid"

type AdminsInOrg struct {
	ID         uuid.UUID `json:"id"`
	Slug       string    `json:"slug"`
	InstanceID string    `json:"instance_id"`
	Admins     []UserDTO `json:"admins"`
}
