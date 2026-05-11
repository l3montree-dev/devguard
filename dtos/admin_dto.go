package dtos

import "github.com/google/uuid"

const (
	CouldNotFindUserWithMail           = "could not find user with the provided mail"
	CouldNotFindDefinitiveUserWithMail = "could not find a definitive user with the provided mail"
)

type AdminsInOrg struct {
	ID         uuid.UUID `json:"id"`
	Slug       string    `json:"slug"`
	InstanceID string    `json:"instance_id"`
	Admins     []UserDTO `json:"admins"`
}
