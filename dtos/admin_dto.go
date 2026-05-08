package dtos

import "github.com/google/uuid"

type AdminsInOrg struct {
	ID         uuid.UUID `json:"id"`
	Slug       string    `json:"slug"`
	InstanceID string    `json:"instance_id"`
	Admins     []UserDTO `json:"admins"`
}

type AddAdminRequest struct {
	OrgID  string `json:"org_id"`
	UserID string `json:"user_id"`
}
