package core

type Repository struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type ThirdPartyIntegration interface {
	IntegrationEnabled(ctx Context) bool

	WantsToHandleWebhook(ctx Context) bool
	HandleWebhook(ctx Context) error

	WantsToFinishInstallation(ctx Context) bool
	FinishInstallation(ctx Context) error

	ListRepositories(ctx Context) ([]Repository, error)

	HandleEvent(event any) error
}
