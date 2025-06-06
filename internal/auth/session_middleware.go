// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type verifier interface {
	VerifyRequestSignature(req *http.Request) (string, string, error)
}

func getCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func cookieAuth(ctx context.Context, oryApiClient *client.APIClient, oryKratosSessionCookie string) (string, error) {
	// check if we have a session
	unescaped, err := url.QueryUnescape(oryKratosSessionCookie)
	if err != nil {
		return "", err
	}

	session, _, err := oryApiClient.FrontendAPI.ToSession(ctx).Cookie(unescaped).Execute()
	if err != nil {
		return "", err
	}

	/*cred, _, err := oryApiClient.IdentityAPI.GetIdentity(ctx, session.Identity.Id).IncludeCredential([]string{"oidc"}).Execute()
	if err != nil {
		panic(err)
	}

	if cred.Credentials != nil {
		// check if oidc creds exist
		creds, ok := (*cred.Credentials)["oidc"]
		if ok {
			// check if we find opencode in the providers
			for _, provider := range creds.Config["providers"].([]interface{}) {
				if provider.(map[string]interface{})["provider"] == "opencode" {
					// print initial_refresh_token and initial_access_token
					fmt.Println(provider.(map[string]interface{})["initial_refresh_token"])
					fmt.Println(provider.(map[string]interface{})["initial_access_token"])
				}
			}
		}
	}*/

	return session.Identity.Id, nil
}

func SessionMiddleware(oryApiClient *client.APIClient, verifier verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			oryKratosSessionCookie := getCookie("ory_kratos_session", ctx.Cookies())

			var userID string
			var scopes string
			var err error

			adminTokenHeader := ctx.Request().Header.Get("X-Admin-Token")

			if oryKratosSessionCookie == nil {
				userID, scopes, err = verifier.VerifyRequestSignature(ctx.Request())
				if err != nil {
					ctx.Set("session", NoSession)
					return next(ctx)
				}
			} else if adminTokenHeader != "" {
				slog.Warn("admin token header is set, using it to create session", "header", adminTokenHeader)
				ctx.Set("session", NewSession(adminTokenHeader, []string{"admin"}))
				return next(ctx)
			} else {
				userID, err = cookieAuth(ctx.Request().Context(), oryApiClient, oryKratosSessionCookie.String())
				if err != nil {
					// user is not authenticated
					// set a special session - it might be that the user is still allowed todo the request
					// since the org, project etc. is public
					slog.Warn("could not get user ID from cookie", "err", err)
					ctx.Set("session", NoSession)
					return next(ctx)
				}

				scopes = "scan manage"
			}

			scopesArray := strings.Fields(scopes)

			ctx.Set("session", NewSession(userID, scopesArray))

			return next(ctx)
		}
	}
}
