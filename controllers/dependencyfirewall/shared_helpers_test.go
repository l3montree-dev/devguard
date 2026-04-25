// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dependencyfirewall

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestEnsureReadMethod(t *testing.T) {
	t.Run("allows GET", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := ensureReadMethod(c); err != nil {
			t.Fatalf("expected GET to be allowed, got error: %v", err)
		}
	})

	t.Run("allows HEAD", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodHead, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := ensureReadMethod(c); err != nil {
			t.Fatalf("expected HEAD to be allowed, got error: %v", err)
		}
	})

	t.Run("rejects POST", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := ensureReadMethod(c)
		if err == nil {
			t.Fatal("expected POST to be rejected")
		}

		httpErr, ok := err.(*echo.HTTPError)
		if !ok {
			t.Fatalf("expected *echo.HTTPError, got %T", err)
		}
		if httpErr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, httpErr.Code)
		}
	})
}

func TestPassthroughUpstreamResponse(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	d := &DependencyProxyController{}
	headers := http.Header{}
	headers.Add("X-Test", "a")
	headers.Add("X-Test", "b")
	headers.Set("Content-Type", "application/json")
	body := []byte(`{"ok":true}`)

	if err := d.passthroughUpstreamResponse(c, headers, http.StatusAccepted, body); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, rec.Code)
	}
	if got := rec.Body.String(); got != string(body) {
		t.Fatalf("expected body %q, got %q", string(body), got)
	}
	if got := rec.Header().Values("X-Test"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected X-Test headers [a b], got %v", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got)
	}
}
