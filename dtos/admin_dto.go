package dtos

import "github.com/google/uuid"

const (
	ErrorCouldNotFindUserWithMail           = "could not find user with the provided mail"
	ErrorCouldNotFindDefinitiveUserWithMail = "could not find a definitive user with the provided mail"
	ErrorInvalidOrMissingOrgID              = "invalid or missing organization id in path parameters"
	ErrorInvalidOrMissingUserID             = "invalid or missing user id in path parameters"
)

type AdminsInOrg struct {
	ID         uuid.UUID `json:"id"`
	Slug       string    `json:"slug"`
	InstanceID string    `json:"instance_id"`
	Admins     []UserDTO `json:"admins"`
}

type OrgInformation struct {
	OwnerEmail string `json:"owner_mail"`
}

type UpdateAssetRequest struct {
	NewSlug string `json:"new_slug"`
}
