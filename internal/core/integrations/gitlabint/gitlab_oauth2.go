package gitlabint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/ory/client-go"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type GitlabOauth2Config struct {
	ProviderID    string
	GitlabBaseURL string

	GitlabOauth2TokenRepository core.GitLabOauth2TokenRepository

	Oauth2Conf *oauth2.Config

	DevGuardBotUserID          int    // the user id of the devguard bot user, used to create issues
	DevGuardBotUserAccessToken string // the access token of the devguard bot user, used to create issues
	AdminToken                 *string
}

func (c *GitlabOauth2Config) GetProviderID() string {
	return c.ProviderID
}

func (c *GitlabOauth2Config) GetBaseURL() string {
	return c.GitlabBaseURL
}

type gitlabEnvConfig struct {
	baseURL            string
	appID              string
	appSecret          string
	scopes             string
	botUserID          int     // the user id of the devguard bot user, used to create issues
	botUserAccessToken string  // the access token of the devguard bot user, used to create issues
	adminToken         *string // the admin token for the gitlab instance, used to create issues
}

type gitlabOauth2Client struct {
	gitlabUserID int
	gitlabClient
}

var httpClientCache = common.NewCacheTransport(1000, 1*time.Hour)

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
			case "scopes":
				conf.scopes = value
			case "botuserid":
				intValue, err := strconv.Atoi(value)
				if err != nil {
					panic(fmt.Sprintf("GITLAB_%s_BOTUSERID is not a valid integer: %s", strings.ToUpper(name), value))
				}
				conf.botUserID = intValue
			case "botuseraccesstoken":
				conf.botUserAccessToken = value
			case "admintoken":
				if value == "" {
					conf.adminToken = nil
				} else {
					conf.adminToken = &value
				}
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

		if conf.scopes == "" {
			panic(fmt.Sprintf("GITLAB_%s_SCOPES is not set", strings.ToUpper(name)))
		}

		if conf.botUserID == 0 {
			slog.Warn(fmt.Sprintf("GITLAB_%s_BOTUSERID is not set", strings.ToUpper(name)))
		}
		if conf.botUserAccessToken == "" {
			slog.Warn(fmt.Sprintf("GITLAB_%s_BOTUSERACCESSTOKEN is not set", strings.ToUpper(name)))
		}
		if conf.adminToken == nil {
			slog.Warn(fmt.Sprintf("GITLAB_%s_ADMINTOKEN is not set", strings.ToUpper(name)))
		} else {
			slog.Info(fmt.Sprintf("GITLAB_%s_ADMINTOKEN is set", strings.ToUpper(name)))
		}
	}

	return urls
}

func NewGitLabOauth2Config(db core.DB, id, gitlabBaseURL, gitlabOauth2ClientID, gitlabOauth2ClientSecret, gitlabOauth2Scopes string, botUserID int, botUserAccessToken string, adminToken *string) *GitlabOauth2Config {

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		panic("FRONTEND_URL is not set")
	}

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		panic("API_URL is not set")
	}

	return &GitlabOauth2Config{
		GitlabBaseURL:              gitlabBaseURL,
		ProviderID:                 id,
		DevGuardBotUserID:          botUserID,
		DevGuardBotUserAccessToken: botUserAccessToken,
		AdminToken:                 adminToken,
		Oauth2Conf: &oauth2.Config{
			ClientID:     gitlabOauth2ClientID,
			ClientSecret: gitlabOauth2ClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/devguard-tunnel/api/v1/oauth2/gitlab/callback/%s", frontendURL, id),
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s/oauth/authorize", gitlabBaseURL),
				TokenURL: fmt.Sprintf("%s/oauth/token", gitlabBaseURL),
			},
			Scopes: strings.Fields(gitlabOauth2Scopes),
		},
		GitlabOauth2TokenRepository: repositories.NewGitlabOauth2TokenRepository(db),
	}
}

type tokenPersister struct {
	next                   oauth2.TokenSource // wrapped token source
	currentToken           models.GitLabOauth2Token
	gitlabOauth2Repository core.GitLabOauth2TokenRepository
}

func newTokenPersister(gitlabOauth2Repository core.GitLabOauth2TokenRepository, token models.GitLabOauth2Token, tokenSource oauth2.TokenSource) *tokenPersister {
	return &tokenPersister{
		next:                   tokenSource,
		currentToken:           token,
		gitlabOauth2Repository: gitlabOauth2Repository,
	}
}

func (t *tokenPersister) Token() (*oauth2.Token, error) {
	token, err := t.next.Token()
	if err != nil {
		return nil, err
	}

	// check if the refresh token has changed
	if token.RefreshToken != "" && token.RefreshToken != t.currentToken.RefreshToken && t.currentToken.Expiry.Before(token.Expiry) {
		// save the new refresh token in the database

		t.currentToken.RefreshToken = token.RefreshToken
		t.currentToken.Expiry = token.Expiry
		t.currentToken.AccessToken = token.AccessToken

		err := t.gitlabOauth2Repository.Save(nil, &t.currentToken)

		if err != nil {
			return nil, err
		}
		slog.Debug("saving new refresh token")
	}
	return token, nil
}

func (c *GitlabOauth2Config) client(token models.GitLabOauth2Token) *http.Client {
	tokenSource := c.Oauth2Conf.TokenSource(context.TODO(), &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	})

	return oauth2.NewClient(context.TODO(), newTokenPersister(c.GitlabOauth2TokenRepository, token, tokenSource))
}

func NewGitLabOauth2Integrations(db core.DB) map[string]*GitlabOauth2Config {
	envs := parseGitlabEnvs()
	gitlabIntegrations := make(map[string]*GitlabOauth2Config)
	for id, env := range envs {
		gitlabIntegration := NewGitLabOauth2Config(db, id, env.baseURL, env.appID, env.appSecret, env.scopes, env.botUserID, env.botUserAccessToken, env.adminToken)
		gitlabIntegrations[id] = gitlabIntegration
		slog.Info("gitlab oauth2 integration created", "id", id, "baseURL", env.baseURL, "appID", env.appID)
	}
	return gitlabIntegrations
}

func (c *GitlabOauth2Config) Oauth2Callback(ctx core.Context) error {
	// get the user
	userID := core.GetSession(ctx).GetUserID()
	code := ctx.QueryParam("code")
	if code == "" {
		return ctx.JSON(400, map[string]any{
			"message": "code is missing",
		})
	}

	// fetch the token model from the database
	tokenModel, err := c.GitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, c.ProviderID)
	if err != nil {
		return ctx.JSON(404, map[string]any{
			"message": "token model not found",
		})
	}

	// check if the verifier is set
	if tokenModel.Verifier == nil {
		return ctx.JSON(400, map[string]any{
			"message": "verifier is missing. Did you call the login endpoint first?",
		})
	}

	token, err := c.Oauth2Conf.Exchange(ctx.Request().Context(), code, oauth2.VerifierOption(*tokenModel.Verifier))
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
	tokenModel.Scopes = strings.Join(c.Oauth2Conf.Scopes, " ")
	// get the gitlab user id by doing a request to the gitlab api
	client := c.client(*tokenModel)
	resp, err := client.Get(fmt.Sprintf("%s/api/v4/user", c.GitlabBaseURL))
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "could not get user",
		})
	}
	if resp.StatusCode != 200 {
		return ctx.JSON(400, map[string]any{
			"message": "could not get user",
		})
	}
	// read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "could not read response body",
		})
	}
	defer resp.Body.Close()
	// unmarshal the response body
	var gitlabUser struct {
		ID int `json:"id"`
	}
	err = json.Unmarshal(body, &gitlabUser)
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "could not unmarshal response body",
		})
	}

	tokenModel.GitLabUserID = gitlabUser.ID

	err = c.GitlabOauth2TokenRepository.Save(nil, tokenModel)
	if err != nil {
		return ctx.JSON(500, map[string]any{
			"message": "could not save token",
		})
	}
	// redirect the user to the frontend
	redirectURL := fmt.Sprintf("%s/@%s", os.Getenv("FRONTEND_URL"), c.ProviderID)

	// check for state
	redirectTo := ctx.QueryParam("state")

	if redirectTo != "" {
		redirectURL = redirectTo
	}

	return ctx.Redirect(302, redirectURL)
}

func (c *GitlabOauth2Config) Oauth2Login(ctx core.Context) error {
	// use PKCE to protect against CSRF attacks
	// https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-countermeasures-6
	verifier := oauth2.GenerateVerifier()
	// get the user
	userID := core.GetSession(ctx).GetUserID()

	redirectTo := ctx.QueryParam("redirectTo")

	url := c.Oauth2Conf.AuthCodeURL(redirectTo, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

	// check if a token model already exists
	tokenModel, err := c.GitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, c.ProviderID)
	if err == nil {
		// it does exist - update the verifier
		tokenModel.Verifier = utils.Ptr(verifier)
		err = c.GitlabOauth2TokenRepository.Save(nil, tokenModel)
		if err != nil {
			return ctx.JSON(500, map[string]any{
				"message": "could not save token",
			})
		}
		return ctx.Redirect(302, url)
	}

	// save the verifier in the database
	tokenModel = &models.GitLabOauth2Token{
		Verifier:   utils.Ptr(verifier),
		UserID:     userID,
		BaseURL:    c.GitlabBaseURL,
		CreatedAt:  time.Now(),
		ProviderID: c.ProviderID,
	}

	err = c.GitlabOauth2TokenRepository.Save(nil, tokenModel)

	if err != nil {
		return err
	}

	// redirect the user to the oauth2 url
	return ctx.Redirect(302, url)
}

func getGitlabAccessTokenFromOryIdentity(oauth2Endpoints map[string]*GitlabOauth2Config, identity client.Identity) (map[string]models.GitLabOauth2Token, error) {
	mapProviderToken := make(map[string]models.GitLabOauth2Token)
	// check if the user has a gitlab login
	// we can even improve the response by checking if the user has a gitlab login
	// todo this, fetch the kratos user and check if the user has a gitlab login
	if identity.Credentials == nil {
		return mapProviderToken, errors.New("no credentials found")
	}

	creds, ok := (*identity.Credentials)["oidc"]
	if !ok {
		return mapProviderToken, errors.New("no oidc credentials found")
	}

	// check if oidc creds exist
	for _, provider := range creds.Config["providers"].([]any) {
		// cast to map[string]interface{}
		provider, ok := provider.(map[string]interface{})
		if !ok {
			continue
		}

		providerName, ok := provider["provider"].(string)
		// check if the providerName is in the oauth2Endpoints
		if !ok || providerName == "" {
			continue
		}

		conf, ok := oauth2Endpoints[providerName]
		if !ok {
			continue
		}

		gitlabUserIdInt, err := strconv.Atoi(provider["subject"].(string))
		if err != nil {
			slog.Error("could not convert gitlab user id to int", "err", err)
			continue
		}

		mapProviderToken[providerName] = models.GitLabOauth2Token{
			AccessToken:  provider["initial_access_token"].(string),
			RefreshToken: provider["initial_refresh_token"].(string),
			BaseURL:      conf.GitlabBaseURL,
			GitLabUserID: gitlabUserIdInt,
			Scopes:       "read_api",                         // I know that!
			Expiry:       creds.UpdatedAt.Add(2 * time.Hour), // this is a guess, we don't know the expiry time
		}
	}

	return mapProviderToken, nil
}
