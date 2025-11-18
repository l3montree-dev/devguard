// Copyright (C) 2025 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"context"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/integrations"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

// TestApp provides access to all services and controllers via FX
type TestApp struct {
	fx.In

	// Core infrastructure
	DB     shared.DB
	Broker shared.Broker

	// Services
	ConfigService            services.ConfigService
	LicenseRiskService       shared.LicenseRiskService
	StatisticsService        shared.StatisticsService
	ComponentService         shared.ComponentService
	FirstPartyVulnService    shared.FirstPartyVulnService
	DependencyVulnService    shared.DependencyVulnService
	ArtifactService          shared.ArtifactService
	AssetVersionService      shared.AssetVersionService
	AssetService             shared.AssetService
	ProjectService           shared.ProjectService
	OrgService               shared.OrgService
	ScanService              shared.ScanService
	CSAFService              shared.CSAFService
	ReleaseService           shared.ReleaseService
	OpenSourceInsightService shared.OpenSourceInsightService

	// Controllers
	AssetController          *controllers.AssetController
	AssetVersionController   *controllers.AssetVersionController
	ScanController           *controllers.ScanController
	ProjectController        *controllers.ProjectController
	OrgController            *controllers.OrgController
	DependencyVulnController *controllers.DependencyVulnController
	FirstPartyVulnController *controllers.FirstPartyVulnController
	ComponentController      *controllers.ComponentController
	ArtifactController       *controllers.ArtifactController
	CSAFController           *controllers.CSAFController

	// Repositories
	AssetRepository             shared.AssetRepository
	AssetVersionRepository      shared.AssetVersionRepository
	ComponentRepository         shared.ComponentRepository
	DependencyVulnRepository    shared.DependencyVulnRepository
	FirstPartyVulnRepository    shared.FirstPartyVulnRepository
	CveRepository               shared.CveRepository
	CweRepository               shared.CweRepository
	ExploitRepository           shared.ExploitRepository
	AffectedComponentRepository shared.AffectedComponentRepository
	ProjectRepository           shared.ProjectRepository
	OrgRepository               shared.OrganizationRepository
	ArtifactRepository          shared.ArtifactRepository
	VulnEventRepository         shared.VulnEventRepository
	ComponentProjectRepository  shared.ComponentProjectRepository
	StatisticsRepository        shared.StatisticsRepository
	LicenseRiskRepository       shared.LicenseRiskRepository
	GitLabOauth2TokenRepository shared.GitLabOauth2TokenRepository
	GitlabIntegrationRepository shared.GitlabIntegrationRepository
	ExternalUserRepository      shared.ExternalUserRepository
	AggregatedVulnRepository    shared.VulnRepository

	// Access Control
	RBACProvider shared.RBACProvider

	// Integrations
	GitlabIntegration    *gitlabint.GitlabIntegration
	IntegrationAggregate shared.IntegrationAggregate
}

// TestAppOptions configures the test application
type TestAppOptions struct {
	// Additional FX options to include
	ExtraOptions []fx.Option
	// Whether to suppress FX logging
	SuppressLogs bool
	// Custom broker (if nil, a default in-memory broker will be provided)
	Broker shared.Broker
}

// NewTestApp creates a test application with all dependencies wired via FX
// It uses the same FX modules as production for consistency
func NewTestApp(t *testing.T, db shared.DB, opts *TestAppOptions) (*TestApp, *fxtest.App, error) {
	if opts == nil {
		opts = &TestAppOptions{SuppressLogs: true}
	}

	var app TestApp

	os.Setenv("RBAC_CONFIG_PATH", "../config/rbac_model.conf")

	fxOptions := []fx.Option{
		// Provide the database
		fx.Provide(func() shared.DB { return db }),

		// Provide broker
		fx.Provide(func() shared.Broker {
			if opts.Broker != nil {
				return opts.Broker
			}
			// Return a no-op broker for tests
			return &noopBroker{}
		}),

		// Use the same modules as production
		repositories.Module,
		services.ServiceModule,
		controllers.ControllerModule,
		accesscontrol.AccessControlModule,
		integrations.Module,
		fx.Decorate(func() utils.FireAndForgetSynchronizer {
			return utils.NewSyncFireAndForgetSynchronizer()
		}),
		fx.Populate(&app),
	}

	// Add extra options if provided
	if len(opts.ExtraOptions) > 0 {
		fxOptions = append(fxOptions, opts.ExtraOptions...)
	}

	// Suppress logs if requested
	if opts.SuppressLogs {
		fxOptions = append(fxOptions, fx.NopLogger)
	}

	fxApp := fxtest.New(t, fxOptions...)

	if err := fxApp.Err(); err != nil {
		return nil, nil, err
	}

	fxApp.RequireStart()

	return &app, fxApp, nil
}

// NewTestAppWithT creates a test application tied to a testing.T
// It automatically stops the app when the test completes
func NewTestAppWithT(t *testing.T, db shared.DB, opts *TestAppOptions) (*TestApp, *fxtest.App) {
	t.Helper()

	app, fxApp, err := NewTestApp(t, db, opts)
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	return app, fxApp
}

// noopBroker is a no-op implementation of the Broker interface for testing
type noopBroker struct{}

func (n *noopBroker) Publish(ctx context.Context, message shared.Message) error {
	return nil
}

func (n *noopBroker) Subscribe(topic shared.Channel) (<-chan map[string]any, error) {
	ch := make(chan map[string]any)
	close(ch) // Return a closed channel so subscribers don't block
	return ch, nil
}
