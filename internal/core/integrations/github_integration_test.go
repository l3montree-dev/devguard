package integrations

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v62/github"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGithubIntegrationHandleEvent(t *testing.T) {
	t.Run("it should not be possible to call handle event with a context without dependencyVulnId parameter", func(t *testing.T) {

		githubIntegration := githubIntegration{}

		req := httptest.NewRequest("POST", "/webhook", nil)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("github:123"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})

		assert.Error(t, err)
	})

	t.Run("it should return an error, if the dependencyVuln could not be found", func(t *testing.T) {
		dependencyVulnRepository := mocks.NewCoreDependencyVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(models.DependencyVuln{}, fmt.Errorf("dependencyVuln not found"))

		githubIntegration := githubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
		}

		req := httptest.NewRequest("POST", "/webhook", nil)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())
		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("github:owner:repo/1"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})
		ctx.SetParamNames("dependencyVulnId", "projectSlug", "orgSlug")
		ctx.SetParamValues("1", "test", "test")

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})
		assert.Error(t, err)
	})

	t.Run("it should do nothing, if the asset is NOT connected to a github repository", func(t *testing.T) {
		// since we are not asserting anything on dependencyVulnRepository nor vulnEventRepository nor github client, we can be sure
		// that no methods were called and actually nothing happened
		githubIntegration := githubIntegration{}

		req := httptest.NewRequest("POST", "/webhook", nil)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())
		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("gitlab:123"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})
		core.SetProject(ctx, models.Project{})
		ctx.SetParamNames("dependencyVulnId", "projectSlug", "orgSlug")
		ctx.SetParamValues("1", "test", "test")

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})
		assert.NoError(t, err)
	})

	t.Run("it should return an error if the owner or repo could not be extracted from the repositoryId", func(t *testing.T) {
		dependencyVulnRepository := mocks.NewCoreDependencyVulnRepository(t)

		githubIntegration := githubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory: func(repoId string) (githubClientFacade, error) {
				return mocks.NewIntegrationsGithubClientFacade(t), nil
			},
			frontendUrl: "http://localhost:3000",
		}

		// create echo context
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(`{"comment": "test"}`))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())
		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("github:1"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})
		core.SetOrgSlug(ctx, "test")
		core.SetProjectSlug(ctx, "test")
		core.SetAssetSlug(ctx, "test")
		core.SetProject(ctx, models.Project{})

		ctx.SetParamNames("dependencyVulnId")
		ctx.SetParamValues("1")

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})

		assert.Error(t, err)
	})

	t.Run("it should return error if could not save the dependencyVuln and the VulnEvent", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(`{"comment": "test"}`))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		dependencyVulnRepository := mocks.NewCoreDependencyVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(models.DependencyVuln{
			CVE: &models.CVE{
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			CVEID:                 utils.Ptr("CVE-2021-1234"),
			RawRiskAssessment:     utils.Ptr(8.5),
			ComponentPurl:         utils.Ptr("pkg:github/owner/repo@1.0.0"),
			ComponentDepth:        utils.Ptr(1),
			ComponentFixedVersion: utils.Ptr("1.0.1"),
		}, nil)
		dependencyVulnRepository.On("ApplyAndSave", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("could not save dependencyVuln"))

		githubClientFactory := func(repoId string) (githubClientFacade, error) {
			facade := mocks.NewIntegrationsGithubClientFacade(t)

			facade.On("CreateIssue", context.Background(), "repo", "1", mock.Anything).Return(&github.Issue{}, &github.Response{}, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "severity:"+"high", &github.Label{
				Description: github.String("Severity of the dependencyVuln"),
				Color:       github.String("FFA500"),
			}).Return(nil, nil, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "devguard", &github.Label{
				Description: github.String("DevGuard"),
				Color:       github.String("182654"),
			}).Return(nil, nil, nil)
			facade.On("EditIssue", context.TODO(), "repo", "1", 0, &github.IssueRequest{
				State: github.String("closed"),
			}).Return(nil, nil, fmt.Errorf("could not close issue"))
			return facade, nil
		}

		githubIntegration := githubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory:      githubClientFactory,
			frontendUrl:              "http://localhost:3000",
		}

		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("github:owner:repo/1"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})
		core.SetOrgSlug(ctx, "test")
		core.SetProjectSlug(ctx, "test")
		core.SetAssetSlug(ctx, "test")
		ctx.SetParamNames("dependencyVulnId")
		ctx.SetParamValues("1")

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})
		assert.Error(t, err)
	})

	t.Run("it should save the justification in the VulnEvent after creating a github ticket. Ref: https://github.com/l3montree-dev/devguard/issues/173", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(`{"comment": "that is a justification"}`))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		expectDependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				TicketID:  utils.Ptr("github:0"),
				TicketURL: utils.Ptr(""),
			},
			CVE: &models.CVE{
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			CVEID:                 utils.Ptr("CVE-2021-1234"),
			RawRiskAssessment:     utils.Ptr(8.5),
			ComponentPurl:         utils.Ptr("pkg:github/owner/repo@1.0.0"),
			ComponentDepth:        utils.Ptr(1),
			ComponentFixedVersion: utils.Ptr("1.0.1"),
		}

		dependencyVulnRepository := mocks.NewCoreDependencyVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(expectDependencyVuln, nil)
		dependencyVulnRepository.On("ApplyAndSave", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		expectedEvent := models.VulnEvent{
			Type:   models.EventTypeMitigate,
			UserID: "1",

			ArbitraryJsonData: "{\"ticketId\":\"github:0\",\"ticketUrl\":\"\"}",

			Justification: utils.Ptr("that is a justification"),
		}
		expectedEvent.GetArbitraryJsonData()

		githubClientFactory := func(repoId string) (githubClientFacade, error) {
			facade := mocks.NewIntegrationsGithubClientFacade(t)

			facade.On("CreateIssue", context.Background(), "repo", "1", mock.Anything).Return(&github.Issue{}, &github.Response{}, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "severity:"+"high", &github.Label{
				Description: github.String("Severity of the dependencyVuln"),
				Color:       github.String("FFA500"),
			}).Return(nil, nil, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "devguard", &github.Label{
				Description: github.String("DevGuard"),
				Color:       github.String("182654"),
			}).Return(nil, nil, nil)
			return facade, nil
		}

		githubIntegration := githubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory:      githubClientFactory,
			frontendUrl:              "http://localhost:3000",
		}

		core.SetAsset(ctx, models.Asset{
			RepositoryID: utils.Ptr("github:owner:repo/1"),
		})
		core.SetAssetVersion(ctx, models.AssetVersion{
			Name: "GenieOderWAHNSINNN",
		})
		core.SetOrgSlug(ctx, "test")
		core.SetProjectSlug(ctx, "test")
		core.SetAssetSlug(ctx, "test")
		ctx.SetParamNames("dependencyVulnId")
		ctx.SetParamValues("1")

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})
		assert.NoError(t, err)
	})

}
func TestGithubTicketIdToIdAndNumber(t *testing.T) {
	t.Run("it should return the correct ticket ID and number for a valid input", func(t *testing.T) {
		id := "github:123456789/123"
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 123456789, ticketId)
		assert.Equal(t, 123, ticketNumber)
	})

	t.Run("it should return 0, 0 if the input format is invalid (missing slash)", func(t *testing.T) {
		id := "github:123456789"
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 0, ticketId)
		assert.Equal(t, 0, ticketNumber)
	})

	t.Run("it should return the correct values, even if the prefix is missing", func(t *testing.T) {
		id := "123456789/123"
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 123456789, ticketId)
		assert.Equal(t, 123, ticketNumber)
	})

	t.Run("it should return 0, 0 if the ticket ID is not a valid integer", func(t *testing.T) {
		id := "github:abc/123"
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 0, ticketId)
		assert.Equal(t, 0, ticketNumber)
	})

	t.Run("it should return 0, 0 if the ticket number is not a valid integer", func(t *testing.T) {
		id := "github:123456789/abc"
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 0, ticketId)
		assert.Equal(t, 0, ticketNumber)
	})

	t.Run("it should return 0, 0 if the input is empty", func(t *testing.T) {
		id := ""
		ticketId, ticketNumber := githubTicketIdToIdAndNumber(id)

		assert.Equal(t, 0, ticketId)
		assert.Equal(t, 0, ticketNumber)
	})
}
