package core

import "github.com/l3montree-dev/devguard/internal/database/models"

type Repository struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type User struct {
	Name      string  `json:"name"`
	ID        string  `json:"id"`
	AvatarURL *string `json:"avatarUrl"`
}
type ThirdPartyIntegration interface {
	IntegrationEnabled(ctx Context) bool

	WantsToHandleWebhook(ctx Context) bool
	HandleWebhook(ctx Context) error

	WantsToFinishInstallation(ctx Context) bool
	FinishInstallation(ctx Context) error

	ListRepositories(ctx Context) ([]Repository, error)

	HandleEvent(event any) error

	GetUsers(org models.Org) []User
}
