package integrations

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"golang.org/x/oauth2"
)

type gitlabOauth2Integration struct {
	id            string
	gitlabBaseURL string

	gitlabIntegrationRepository core.GitlabIntegrationRepository
	gitlabOauth2TokenRepository core.GitLabOauth2TokenRepository

	externalUserRepository core.ExternalUserRepository

	firstPartyVulnRepository core.FirstPartyVulnRepository
	aggregatedVulnRepository core.VulnRepository
	//TODO: remove this
	dependencyVulnRepository core.DependencyVulnRepository
	vulnEventRepository      core.VulnEventRepository
	frontendUrl              string
	orgRepository            core.OrganizationRepository

	projectRepository      core.ProjectRepository
	assetRepository        core.AssetRepository
	assetVersionRepository core.AssetVersionRepository
	componentRepository    core.ComponentRepository

	gitlabClientFactory func(id uuid.UUID) (gitlabClientFacade, error)

	oauth2Conf *oauth2.Config
}

type gitlabEnvConfig struct {
	baseURL   string
	appID     string
	appSecret string
}

func parseGitlabEnvs() map[string]gitlabEnvConfig {
	urls := make(map[string]gitlabEnvConfig)
	for _, env := range os.Environ() {
		// env is in the form "KEY=value"
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if strings.HasPrefix(key, "GITLAB_") {
			// there should be a "BASE_URL", "APP_ID", "APP_SECRET" and "REDIRECT_URL" env var
			// get the name of the instance - between GITLAB_ and _
			name := strings.TrimPrefix(key, "GITLAB_")
			name = strings.ToLower(strings.Split(name, "_")[0])
			// check what kind of value this is
			valueName := strings.TrimPrefix(strings.ToLower(key), "gitlab_"+name+"_")
			// lowercase the value name
			valueName = strings.ToLower(valueName)
			var conf gitlabEnvConfig
			if _, ok := urls[name]; !ok {
				conf = gitlabEnvConfig{}
			} else {
				conf = urls[name]
			}

			switch valueName {
			case "baseurl":
				conf.baseURL = value
			case "appid":
				conf.appID = value
			case "appsecret":
				conf.appSecret = value
			}

			urls[name] = conf
		}
	}
	// check if all values are set
	for name, conf := range urls {
		if conf.baseURL == "" {
			panic(fmt.Sprintf("GITLAB_%s_BASEURL is not set", strings.ToUpper(name)))
		}
		if conf.appID == "" {
			panic(fmt.Sprintf("GITLAB_%s_APPID is not set", strings.ToUpper(name)))
		}
		if conf.appSecret == "" {
			panic(fmt.Sprintf("GITLAB_%s_APPSECRET is not set", strings.ToUpper(name)))
		}

	}

	return urls
}

func NewGitLabOauth2Integration(db core.DB, id, gitlabBaseURL, gitlabOauth2ClientID, gitlabOauth2ClientSecret string) *gitlabOauth2Integration {
	gitlabIntegrationRepository := repositories.NewGitLabIntegrationRepository(db)

	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	externalUserRepository := repositories.NewExternalUserRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)

	orgRepository := repositories.NewOrgRepository(db)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	apiUrl := os.Getenv("API_URL")
	if apiUrl == "" {
		panic("API_URL is not set")
	}

	return &gitlabOauth2Integration{
		gitlabBaseURL: gitlabBaseURL,
		id:            id,
		oauth2Conf: &oauth2.Config{
			ClientID:     gitlabOauth2ClientID,
			ClientSecret: gitlabOauth2ClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/v1/oauth2/gitlab/callback/%s", apiUrl, id),
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s/oauth/authorize", gitlabBaseURL),
				TokenURL: fmt.Sprintf("%s/oauth/token", gitlabBaseURL),
			},
			Scopes: []string{"api"},
		},
		gitlabOauth2TokenRepository: repositories.NewGitlabOauth2TokenRepository(db),

		frontendUrl:                 frontendUrl,
		aggregatedVulnRepository:    aggregatedVulnRepository,
		gitlabIntegrationRepository: gitlabIntegrationRepository,
		dependencyVulnRepository:    dependencyVulnRepository,
		vulnEventRepository:         vulnEventRepository,
		assetRepository:             assetRepository,
		assetVersionRepository:      assetVersionRepository,
		externalUserRepository:      externalUserRepository,
		firstPartyVulnRepository:    firstPartyVulnRepository,
		projectRepository:           projectRepository,
		componentRepository:         componentRepository,
		orgRepository:               orgRepository,

		gitlabClientFactory: func(id uuid.UUID) (gitlabClientFacade, error) {
			integration, err := gitlabIntegrationRepository.Read(id)
			if err != nil {
				return nil, err
			}
			client, err := gitlab.NewClient(integration.AccessToken, gitlab.WithBaseURL(integration.GitLabUrl))

			if err != nil {
				return nil, err
			}

			return gitlabClient{Client: client, GitLabIntegration: integration}, nil
		},
	}
}

func NewGitLabOauth2Integrations(db core.DB) map[string]*gitlabOauth2Integration {
	envs := parseGitlabEnvs()
	gitlabIntegrations := make(map[string]*gitlabOauth2Integration)
	for id, env := range envs {
		gitlabIntegration := NewGitLabOauth2Integration(db, id, env.baseURL, env.appID, env.appSecret)
		gitlabIntegrations[id] = gitlabIntegration
		slog.Info("gitlab oauth2 integration created", "id", id, "baseURL", env.baseURL, "appID", env.appID)
	}
	return gitlabIntegrations
}

func (c *gitlabOauth2Integration) Oauth2Callback(ctx core.Context) error {
	// get the user
	userID := core.GetSession(ctx).GetUserID()
	code := ctx.QueryParam("code")
	if code == "" {
		return ctx.JSON(400, map[string]any{
			"message": "code is missing",
		})
	}

	// fetch the token model from the database
	tokenModel, err := c.gitlabOauth2TokenRepository.FindByUserIdAndBaseURL(userID, c.gitlabBaseURL)
	if err != nil {
		return ctx.JSON(404, map[string]any{
			"message": "token model not found",
		})
	}

	token, err := c.oauth2Conf.Exchange(ctx.Request().Context(), code, oauth2.VerifierOption(*tokenModel.Verifier))
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "could not exchange code for token",
		})
	}

	tokenModel.Verifier = nil
	// update the token model with the new token
	tokenModel.AccessToken = token.AccessToken
	tokenModel.RefreshToken = token.RefreshToken
	tokenModel.Expiry = token.Expiry
	tokenModel.Scopes = "api"

	err = c.gitlabOauth2TokenRepository.Save(nil, tokenModel)
	if err != nil {
		return ctx.JSON(500, map[string]any{
			"message": "could not save token",
		})
	}

	return ctx.JSON(200, map[string]any{
		"message": "token saved",
	})
}

func (c *gitlabOauth2Integration) Oauth2Login(ctx core.Context) error {
	// use PKCE to protect against CSRF attacks
	// https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-countermeasures-6
	verifier := oauth2.GenerateVerifier()
	// get the user
	userID := core.GetSession(ctx).GetUserID()

	url := c.oauth2Conf.AuthCodeURL("", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

	// save the verifier in the database
	tokenModel := models.GitLabOauth2Token{
		Verifier:  utils.Ptr(verifier),
		UserID:    userID,
		BaseURL:   c.gitlabBaseURL,
		CreatedAt: time.Now(),
	}

	err := c.gitlabOauth2TokenRepository.Save(nil, &tokenModel)

	if err != nil {
		return err
	}

	// redirect the user to the oauth2 url
	return ctx.Redirect(302, url)
}
