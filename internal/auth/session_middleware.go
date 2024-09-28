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
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type verifier interface {
	VerifyRequestSignature(req *http.Request) (string, error)
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
	session, _, err := oryApiClient.FrontendAPI.ToSession(ctx).Cookie(oryKratosSessionCookie).Execute()
	if err != nil {
		return "", err
	}
	return session.Identity.Id, nil
}

func SessionMiddleware(oryApiClient *client.APIClient, verifier verifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			oryKratosSessionCookie := getCookie("ory_kratos_session", c.Cookies())

			var userID string
			var err error

			if oryKratosSessionCookie == nil {
				userID, err = verifier.VerifyRequestSignature(c.Request())
				if err != nil {
					c.Set("session", NoSession)
					return next(c)
				}
			} else {
				userID, err = cookieAuth(c.Request().Context(), oryApiClient, oryKratosSessionCookie.String())
				if err != nil {
					// user is not authenticated
					// set a special session - it might be that the user is still allowed todo the request
					// since the org, project etc. is public
					c.Set("session", NoSession)
					return next(c)
				}
			}

			c.Set("session", NewSession(userID))

			return next(c)
		}
	}
}
