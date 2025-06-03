package githubint

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v62/github"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGithubIntegrationHandleEvent(t *testing.T) {
	t.Run("it should not be possible to call handle event with a context without dependencyVulnId parameter", func(t *testing.T) {

		githubIntegration := GithubIntegration{}

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
		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(models.DependencyVuln{}, fmt.Errorf("dependencyVuln not found"))

		githubIntegration := GithubIntegration{
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
		githubIntegration := GithubIntegration{}

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
		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(models.DependencyVuln{}, nil)

		githubIntegration := GithubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory: func(repoId string) (githubClientFacade, error) {
				return mocks.NewGithubClientFacade(t), nil
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
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")

		core.SetSession(ctx, authSession)

		err := githubIntegration.HandleEvent(core.ManualMitigateEvent{
			Ctx: ctx,
		})

		assert.Error(t, err)
	})

	t.Run("it should return error if could not save the dependencyVuln and the VulnEvent", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(`{"comment": "test"}`))
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())
		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]models.ComponentDependency{}, nil)

		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		aggregatedVulnRepository := mocks.NewVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				ID: "abc",
			},
			CVE: &models.CVE{
				Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			CVEID:                 utils.Ptr("CVE-2021-1234"),
			RawRiskAssessment:     utils.Ptr(8.5),
			ComponentPurl:         utils.Ptr("pkg:github/owner/repo@1.0.0"),
			ComponentDepth:        utils.Ptr(1),
			ComponentFixedVersion: utils.Ptr("1.0.1"),
		}, nil)
		aggregatedVulnRepository.On("ApplyAndSave", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("could not save dependencyVuln"))

		githubClientFactory := func(repoId string) (githubClientFacade, error) {
			facade := mocks.NewGithubClientFacade(t)

			facade.On("CreateIssue", context.Background(), "repo", "1", mock.Anything).Return(&github.Issue{}, &github.Response{}, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "risk:"+"high", &github.Label{
				Description: github.String("Calculated risk of the vulnerability (based on CVSS, EPSS, and other factors)"),
				Color:       github.String("FFA500"),
			}).Return(nil, nil, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "devguard", &github.Label{
				Description: github.String("DevGuard"),
				Color:       github.String("182654"),
			}).Return(nil, nil, nil)
			facade.On("EditIssue", context.TODO(), "repo", "1", 0, &github.IssueRequest{
				State: github.String("closed"),
			}).Return(nil, nil, fmt.Errorf("could not close issue"))
			facade.On(("CreateIssueComment"), context.Background(), "repo", "1", 0, mock.Anything).Return(&github.IssueComment{}, &github.Response{}, nil)
			return facade, nil
		}

		githubIntegration := GithubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory:      githubClientFactory,
			frontendUrl:              "http://localhost:3000",
			componentRepository:      componentRepository,
			aggregatedVulnRepository: aggregatedVulnRepository,
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

		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetSession(ctx, authSession)

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
				ID:        "abc",
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

		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		aggregatedVulnRepository := mocks.NewVulnRepository(t)
		dependencyVulnRepository.On("Read", "1").Return(expectDependencyVuln, nil)
		aggregatedVulnRepository.On("ApplyAndSave", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		componentRepository := mocks.NewComponentRepository(t)
		componentRepository.On("LoadPathToComponent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]models.ComponentDependency{}, nil)

		expectedEvent := models.VulnEvent{
			Type:   models.EventTypeMitigate,
			UserID: "1",

			ArbitraryJsonData: "{\"ticketId\":\"github:0\",\"ticketUrl\":\"\"}",

			Justification: utils.Ptr("that is a justification"),
		}
		expectedEvent.GetArbitraryJsonData()

		githubClientFactory := func(repoId string) (githubClientFacade, error) {
			facade := mocks.NewGithubClientFacade(t)

			facade.On("CreateIssue", context.Background(), "repo", "1", mock.Anything).Return(&github.Issue{}, &github.Response{}, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "risk:"+"high", &github.Label{
				Description: github.String("Calculated risk of the vulnerability (based on CVSS, EPSS, and other factors)"),
				Color:       github.String("FFA500"),
			}).Return(nil, nil, nil)
			facade.On("EditIssueLabel", context.Background(), "repo", "1", "devguard", &github.Label{
				Description: github.String("DevGuard"),
				Color:       github.String("182654"),
			}).Return(nil, nil, nil)
			facade.On("CreateIssueComment", context.Background(), "repo", "1", 0, mock.Anything).Return(&github.IssueComment{}, &github.Response{}, nil)
			return facade, nil
		}

		githubIntegration := GithubIntegration{
			dependencyVulnRepository: dependencyVulnRepository,
			githubClientFactory:      githubClientFactory,
			frontendUrl:              "http://localhost:3000",
			componentRepository:      componentRepository,
			aggregatedVulnRepository: aggregatedVulnRepository,
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

		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("1")
		core.SetSession(ctx, authSession)

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
func TestGetLabels(t *testing.T) {
	t.Run("it should return labels with devguard and risk severity", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			RawRiskAssessment: utils.Ptr(8.0),
			CVE: &models.CVE{
				CVSS: 8.0,
			},
		}

		labels := commonint.GetLabels(vuln)

		assert.Contains(t, labels, "devguard")
		assert.Contains(t, labels, "risk:high")
		assert.Contains(t, labels, "state:unknown")
	})

	t.Run("it should include state label if dependency vuln has a state", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateAccepted,
			},
			RawRiskAssessment: utils.Ptr(5.0),
			CVE: &models.CVE{
				CVSS: 5.0,
			},
		}

		labels := commonint.GetLabels(vuln)

		assert.Contains(t, labels, "state:accepted")
		assert.Contains(t, labels, "risk:medium")
	})

	t.Run("it should include cvss-severity label for DependencyVuln", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			CVE: &models.CVE{
				CVSS: 9.8,
			},
		}
		vuln.RawRiskAssessment = utils.Ptr(9.8)

		labels := commonint.GetLabels(vuln)

		assert.Contains(t, labels, "cvss-severity:critical")
		assert.Contains(t, labels, "risk:critical")
	})

	t.Run("it should handle nil CVE gracefully for DependencyVuln", func(t *testing.T) {
		vuln := &models.DependencyVuln{}
		vuln.RawRiskAssessment = utils.Ptr(4.0)

		labels := commonint.GetLabels(vuln)

		assert.Contains(t, labels, "risk:medium")

	})

	t.Run("it should not include risk:none labels", func(t *testing.T) {
		vuln := &models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State: models.VulnStateFalsePositive,
			},
			CVE: &models.CVE{
				CVSS: 0.0,
			},
		}
		vuln.RawRiskAssessment = utils.Ptr(0.0)

		labels := commonint.GetLabels(vuln)

		assert.Contains(t, labels, "state:false-positive")
	})
}

func TestIsGithubUserAuthorized(t *testing.T) {
	t.Run("If the provided user is a member of the project we want to return true", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Repo:   &github.Repository{Owner: &github.User{Login: utils.Ptr("l3monMan")}, Name: utils.Ptr("l3monRepo")},
			Sender: &github.User{ID: utils.Ptr(int64(484662))},
		}
		client := mocks.NewGithubClientFacade(t)
		client.On("IsCollaboratorInRepository", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.True(t, isAuthorized)
	})
	t.Run("If the provided user is not a member of the project we want to return false", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Repo:   &github.Repository{Owner: &github.User{Login: utils.Ptr("l3monMan")}, Name: utils.Ptr("l3monRepo")},
			Sender: &github.User{ID: utils.Ptr(int64(484662))},
		}
		client := mocks.NewGithubClientFacade(t)
		client.On("IsCollaboratorInRepository", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil)
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.False(t, isAuthorized)
	})
	t.Run("If the participation check of the user in the project runs into an error we also want to return that error", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Repo:   &github.Repository{Owner: &github.User{Login: utils.Ptr("l3monMan")}, Name: utils.Ptr("l3monRepo")},
			Sender: &github.User{ID: utils.Ptr(int64(484662))},
		}
		client := mocks.NewGithubClientFacade(t)
		client.On("IsCollaboratorInRepository", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, fmt.Errorf("the github api was blown into pieces"))
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Equal(t, "the github api was blown into pieces", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the provided user is nil we want to abort", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Repo: &github.Repository{Owner: &github.User{Login: utils.Ptr("l3monMan")}, Name: utils.Ptr("l3monRepo")},
		}
		client := mocks.NewGithubClientFacade(t)
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the provided repo is nil we want to abort", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Sender: &github.User{ID: utils.Ptr(int64(484662))},
		}
		client := mocks.NewGithubClientFacade(t)
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the provided owner is nil we want to abort", func(t *testing.T) {
		event := github.IssueCommentEvent{
			Repo:   &github.Repository{},
			Sender: &github.User{ID: utils.Ptr(int64(484662))},
		}
		client := mocks.NewGithubClientFacade(t)
		isAuthorized, err := isGithubUserAuthorized(&event, client)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the passed event is nil we also want to abort", func(t *testing.T) {
		isAuthorized, err := isGithubUserAuthorized(nil, nil)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
}
