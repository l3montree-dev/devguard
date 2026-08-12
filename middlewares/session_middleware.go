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
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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
			instanceSettings, err := configService.GetInstanceSettings(ctx.Request().Context())
			if err != nil {
				return err
			}

			oryKratosSessionCookie := getCookie("ory_kratos_session", ctx.Cookies())
			if oryKratosSessionCookie != nil { // found a cookie, try to authenticate with it
				if userID, err := cookieAuth(ctx.Request().Context(), oryAPIClient, oryKratosSessionCookie.String()); err == nil {
					// successful authentication; set session and continue
					shared.SetSession(ctx, shared.NewSession(userID, shared.SessionActorUser, strings.Fields("scan manage"), false))
					return next(ctx)
				} else {
					slog.Warn("could not get session from cookie", "error", err)
				}
			}

			// try to authenticate via bearer tokens
			if !instanceSettings.BearerTokenAuthDisabled {
				authHeader := ctx.Request().Header.Get("Authorization")
				if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok { // check if a token can be parsed
					if session, err := verifier.VerifyAPIToken(ctx.Request().Context(), token); err == nil { // then verify the token
						shared.SetSession(ctx, session)
						return next(ctx)
					}
				}
			}

			// lastly check if we can authenticate via the request signature
			if session, err := verifier.VerifyRequestSignature(ctx.Request().Context(), ctx.Request()); err == nil {
				shared.SetSession(ctx, session)
				return next(ctx)
			}

			// could not authenticate; set to anonymous
			shared.SetSession(ctx, shared.AnonymousSession)
			return next(ctx)
		}
	}
}
