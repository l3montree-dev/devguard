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

package middleware

import (
	"context"
	"net/http"

	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

func getCookie(name string, cookies []*http.Cookie) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func cookieAuth(ctx context.Context, oryApiClient *client.APIClient, oryKratosSessionCookie string) (*client.Session, *http.Response, error) {
	// check if we have a session
	return oryApiClient.FrontendApi.ToSession(ctx).Cookie(oryKratosSessionCookie).Execute()
}

func patAuth(ctx context.Context, patRepository *repositories.GormPatRepository, oryApiClient *client.APIClient, header string) (*client.Session, *http.Response, error) {
	// get the user id from the database.
	// check if we need to strip a bearer prefix
	if len(header) > 7 && header[:7] == "Bearer " {
		header = header[7:]
	}
	pat, err := patRepository.ReadByToken(header)
	if err != nil {
		return nil, nil, err
	}

	// now we know the user id - lets gSet the session
	identity, resp, err := oryApiClient.IdentityApi.GetIdentity(ctx, pat.UserID.String()).Execute()

	if err != nil {
		return nil, resp, err
	}

	return &client.Session{
		Active:   &[]bool{true}[0],
		Identity: *identity,
	}, resp, nil
}

func SessionMiddleware(oryApiClient *client.APIClient, patRepository *repositories.GormPatRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {

			oryKratosSessionCookie := getCookie("ory_kratos_session", c.Cookies())

			var session *client.Session

			if oryKratosSessionCookie == nil {
				// check for authorization header
				authorizationHeader := c.Request().Header.Get("Authorization")
				if authorizationHeader == "" {
					return c.JSON(401, map[string]string{"error": "no session"})
				}
				session, _, err = patAuth(c.Request().Context(), patRepository, oryApiClient, authorizationHeader)
			} else {
				session, _, err = cookieAuth(c.Request().Context(), oryApiClient, oryKratosSessionCookie.String())
			}

			if (err != nil && session == nil) || (err == nil && !*session.Active) {
				return c.JSON(401, map[string]string{"error": "no session"})
			}

			c.Set("session", auth.NewOrySession(session))
			c.Set("sessionCookie", oryKratosSessionCookie)

			return next(c)
		}
	}
}
