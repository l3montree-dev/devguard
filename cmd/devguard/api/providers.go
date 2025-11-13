// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"os"

	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/auth"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/githubint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/integrations/jiraint"
	"github.com/l3montree-dev/devguard/integrations/webhook"
	"github.com/l3montree-dev/devguard/pubsub"
	"github.com/l3montree-dev/devguard/shared"
)

// AuthModule provides authentication-related dependencies
var AuthModule = fx.Options(
	fx.Provide(func() shared.AdminClient {
		ory := auth.GetOryAPIClient(os.Getenv("ORY_KRATOS_PUBLIC"))
		return shared.NewAdminClient(ory)
	}),
	fx.Provide(func(db shared.DB, broker pubsub.Broker) (shared.RBACProvider, error) {
		return accesscontrol.NewCasbinRBACProvider(db, broker)
	}),
)

// IntegrationModule provides third-party integration dependencies
var IntegrationModule = fx.Options(
	fx.Provide(webhook.NewWebhookIntegration),
	fx.Provide(jiraint.NewJiraIntegration),
	fx.Provide(githubint.NewGithubIntegration),
	fx.Provide(gitlabint.NewGitLabOauth2Integrations),
	fx.Provide(gitlabint.NewGitlabClientFactory),
	fx.Provide(gitlabint.NewGitlabIntegration),
	fx.Provide(integrations.NewThirdPartyIntegrations),
)

// MiddlewareProvider represents a named middleware with its factory function
type MiddlewareProvider struct {
	Name string
	Func shared.MiddlewareFunc
}

// AsMiddleware annotates the result for the middleware value group
type AsMiddleware struct {
	fx.Out

	Middleware MiddlewareProvider `group:"middlewares"`
}

// ProvideExternalEntityProviderOrgSyncMiddleware provides the org sync middleware
func ProvideExternalEntityProviderOrgSyncMiddleware(
	externalEntityProviderService shared.ExternalEntityProviderService,
) AsMiddleware {
	return AsMiddleware{
		Middleware: MiddlewareProvider{
			Name: "externalEntityProviderOrgSync",
			Func: externalEntityProviderOrgSyncMiddleware(externalEntityProviderService),
		},
	}
}

// ProvideExternalEntityProviderRefreshMiddleware provides the entity refresh middleware
func ProvideExternalEntityProviderRefreshMiddleware(
	externalEntityProviderService shared.ExternalEntityProviderService,
) AsMiddleware {
	return AsMiddleware{
		Middleware: MiddlewareProvider{
			Name: "externalEntityProviderRefresh",
			Func: externalEntityProviderRefreshMiddleware(externalEntityProviderService),
		},
	}
}

// MiddlewareModule provides all middleware constructors as a value group
var MiddlewareModule = fx.Options(
	fx.Provide(ProvideExternalEntityProviderOrgSyncMiddleware),
	fx.Provide(ProvideExternalEntityProviderRefreshMiddleware),
)

// MiddlewareRegistry holds all registered middlewares by name
type MiddlewareRegistry struct {
	middlewares map[string]shared.MiddlewareFunc
}

// NewMiddlewareRegistry creates a registry from the value group
func NewMiddlewareRegistry(middlewares []MiddlewareProvider) *MiddlewareRegistry {
	registry := &MiddlewareRegistry{
		middlewares: make(map[string]shared.MiddlewareFunc),
	}
	for _, m := range middlewares {
		registry.middlewares[m.Name] = m.Func
	}
	return registry
}

// Get retrieves a middleware by name
func (r *MiddlewareRegistry) Get(name string) shared.MiddlewareFunc {
	return r.middlewares[name]
}

// MiddlewareRegistryParams is used to consume the middleware value group
type MiddlewareRegistryParams struct {
	fx.In

	Middlewares []MiddlewareProvider `group:"middlewares"`
}

// ProvideMiddlewareRegistry creates the registry from all provided middlewares
func ProvideMiddlewareRegistry(params MiddlewareRegistryParams) *MiddlewareRegistry {
	return NewMiddlewareRegistry(params.Middlewares)
}

// Module combines all API-level FX modules
var Module = fx.Options(
	AuthModule,
	IntegrationModule,
	MiddlewareModule,
	fx.Provide(ProvideMiddlewareRegistry),
)
