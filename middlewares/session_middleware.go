// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

package middlewares

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

func getCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func cookieAuth(ctx context.Context, oryAPIClient shared.PublicClient, oryKratosSessionCookie string) (string, error) {
	// check if we have a session
	unescaped, err := url.QueryUnescape(oryKratosSessionCookie)
	if err != nil {
		return "", err
	}

	session, err := oryAPIClient.GetIdentityFromCookie(ctx, unescaped)
	if err != nil {
		return "", err
	}

	return session.Id, nil
}

func SessionMiddleware(oryAPIClient shared.PublicClient, configService shared.ConfigService, verifier shared.Verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			oryKratosSessionCookie := getCookie("ory_kratos_session", ctx.Cookies())
			instanceSettings, err := configService.GetInstanceSettings(ctx.Request().Context())
			if err != nil {
				return err
			}
			authHeader := ctx.Request().Header.Get("Authorization")

			var userID string
			var scopes string

			if oryKratosSessionCookie != nil {
				if userID, err = cookieAuth(ctx.Request().Context(), oryAPIClient, oryKratosSessionCookie.String()); err == nil {
					scopes = "scan manage"
					scopesArray := strings.Fields(scopes)
					ctx.Set("session", accesscontrol.NewSession(userID, scopesArray, false))
					return next(ctx)
				}
			}
			if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok && !instanceSettings.BearerTokenAuthDisabled {
				if userID, scopes, err = verifier.VerifyAPIToken(ctx.Request().Context(), token); err == nil {
					scopesArray := strings.Fields(scopes)
					ctx.Set("session", accesscontrol.NewSession(userID, scopesArray, false))
					return next(ctx)
				}
			} else {
				if session, err := verifier.VerifyRequestSignature(ctx.Request().Context(), ctx.Request()); err == nil {
					ctx.Set("session", session)
					return next(ctx)
				}
			}

			ctx.Set("session", accesscontrol.NoSession)
			return next(ctx)
		}
	}
}
