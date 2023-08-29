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
	"net/http"

	"github.com/l3montree-dev/flawfix/internal/auth"
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

func SessionMiddleware(oryApiClient *client.APIClient) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {

			oryKratosSessionCookie := getCookie("ory_kratos_session", c.Cookies())
			if oryKratosSessionCookie == nil {
				return c.JSON(401, map[string]string{"error": "no session cookie"})
			}

			// check if we have a session
			session, _, err := oryApiClient.FrontendApi.ToSession(c.Request().Context()).Cookie(oryKratosSessionCookie.String()).Execute()

			if (err != nil && session == nil) || (err == nil && !*session.Active) {
				return c.JSON(401, map[string]string{"error": "no session"})
			}

			c.Set("session", auth.NewOrySession(session))
			c.Set("sessionCookie", oryKratosSessionCookie)

			return next(c)
		}
	}
}
