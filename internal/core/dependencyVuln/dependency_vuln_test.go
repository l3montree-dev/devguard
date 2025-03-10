package dependencyVuln_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func TestCreateIssueForUpdatedVulns(t *testing.T) {
	t.Run("Test with empty threshold and empty slice should return nil", func(t *testing.T) {

		core.LoadConfig() // nolint: errcheck
		os.Setenv("POSTGRES_USER", "devguard")
		os.Setenv("POSTGRES_PASSWORD", "devguard")
		os.Setenv("POSTGRES_DB", "devguard")
		os.Setenv("POSTGRES_HOST", "localhost")
		os.Setenv("POSTGRES_PORT", "5432")
		os.Setenv("FRONTEND_URL", "http://localhost:3000")

		core.InitLogger()
		db, err := core.DatabaseFactory()
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		asset := models.Asset{}

		githubIntegration := integrations.NewGithubIntegration(db)
		gitlabIntegration := integrations.NewGitLabIntegration(db)
		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

		err = dependencyVuln.CreateIssuesForUpdatedVulns(db, thirdPartyIntegration, asset, []models.DependencyVuln{})

		if err != nil {
			t.Fail()
		}
	})
	t.Run("Test with empty threshold and non empty slice should return nil", func(t *testing.T) {

		core.LoadConfig() // nolint: errcheck
		os.Setenv("POSTGRES_USER", "devguard")
		os.Setenv("POSTGRES_PASSWORD", "devguard")
		os.Setenv("POSTGRES_DB", "devguard")
		os.Setenv("POSTGRES_HOST", "localhost")
		os.Setenv("POSTGRES_PORT", "5432")

		core.InitLogger()
		db, err := core.DatabaseFactory()
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		asset := models.Asset{}

		githubIntegration := integrations.NewGithubIntegration(db)
		gitlabIntegration := integrations.NewGitLabIntegration(db)
		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

		err = dependencyVuln.CreateIssuesForUpdatedVulns(db, thirdPartyIntegration, asset, []models.DependencyVuln{
			{
				RawRiskAssessment: utils.Ptr(2.),
				CVE: &models.CVE{
					CVSS: 4,
				},
			},
		})

		if err != nil {
			t.Fail()
		}
	})
	t.Run("Test with valid thresholds and non empty slice should return nil", func(t *testing.T) {

		core.LoadConfig() // nolint: errcheck
		os.Setenv("POSTGRES_USER", "devguard")
		os.Setenv("POSTGRES_PASSWORD", "devguard")
		os.Setenv("POSTGRES_DB", "devguard")
		os.Setenv("POSTGRES_HOST", "localhost")
		os.Setenv("POSTGRES_PORT", "5432")

		core.InitLogger()
		db, err := core.DatabaseFactory()
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}
		p := 4.
		q := 4.

		asset := models.Asset{
			RiskAutomaticTicketThreshold: &p,
			CVSSAutomaticTicketThreshold: &q,
		}

		githubIntegration := integrations.NewGithubIntegration(db)
		gitlabIntegration := integrations.NewGitLabIntegration(db)
		thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

		err = dependencyVuln.CreateIssuesForUpdatedVulns(db, thirdPartyIntegration, asset, []models.DependencyVuln{
			{
				RawRiskAssessment: utils.Ptr(2.),
				CVE: &models.CVE{
					CVSS: 4,
				},
			},
		})

		if err != nil {
			t.Fail()
		}
	})

}
