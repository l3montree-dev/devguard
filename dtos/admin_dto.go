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

type UpdateInstanceSettingsRequest struct {
	DisableOrgCreation *bool `json:"disable_org_creation"` // pointer makes it nil-able so we can distinguish a missing/ incorrectly parsed value (rather than the default value = false)
}
