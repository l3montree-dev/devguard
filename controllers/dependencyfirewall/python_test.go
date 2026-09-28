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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

func TestPyPIParsePackage(t *testing.T) {
	cases := []struct {
		path            string
		expectedPkg     string
		expectedVersion string
	}{
		{"/simple/requests/", "requests", ""},
		{"/packages/ab/cd/requests-2.31.0-py3-none-any.whl", "requests", "2.31.0"},
		{"/packages/ab/cd/requests-2.31.0-py3-none-any.whl/", "requests", "2.31.0"},
		{"/packages/ab/cd/requests-2.32.3.tar.gz", "requests", "2.32.3"},
		{"/packages/ab/cd/Zope.Interface-6.0.tar.gz", "zope-interface", "6.0"},
		{"/packages/ab/cd/python-dateutil-2.9.0.post0.tar.gz", "python-dateutil", "2.9.0.post0"},
		{"/packages/ab/cd/six-1.0.tar.bz2", "six", "1.0"},
		// PEP 658 core metadata files belong to the distribution they describe
		{"/packages/ea/03/92d3/requests-2.11.1-py2.py3-none-any.whl.metadata", "requests", "2.11.1"},
		{"/packages/ab/cd/charset_normalizer-3.5.1-cp313-cp313-macosx_10_13_universal2.whl.metadata", "charset-normalizer", "3.5.1"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			pkg, version := pypi.parsePackage(tc.path)
			if pkg != tc.expectedPkg || version != tc.expectedVersion {
				t.Fatalf("expected %s@%s, got %q@%q", tc.expectedPkg, tc.expectedVersion, pkg, version)
			}
		})
	}
}

func TestPyPIEcosystemTrimPrefix(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "without secret",
			path:     "/api/v1/dependency-proxy/pypi/simple/requests/",
			expected: "simple/requests/",
		},
		{
			name:     "with secret",
			path:     "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/pypi/simple/requests/",
			expected: "simple/requests/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pypi.trimPrefix(tc.path); got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

type simpleIndexTransport struct {
	contentType string
	body        string
}

func (s simpleIndexTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/simple/requests" {
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {s.contentType}},
		Body:       io.NopCloser(strings.NewReader(s.body)),
	}, nil
}

func TestProxyPyPISimpleRewritesFileURLs(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		contentType string
		upstream    string
		expected    string
	}{
		{
			name:        "html without secret",
			path:        "/api/v1/dependency-proxy/pypi/simple/requests/",
			contentType: "text/html",
			upstream:    `<a href="https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl#sha256=abc">requests-2.31.0-py3-none-any.whl</a>`,
			expected:    `<a href="/api/v1/dependency-proxy/pypi/packages/ab/cd/requests-2.31.0-py3-none-any.whl#sha256=abc">requests-2.31.0-py3-none-any.whl</a>`,
		},
		{
			name:        "json with secret",
			path:        "/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/pypi/simple/requests/",
			contentType: "application/vnd.pypi.simple.v1+json",
			upstream:    `{"files":[{"url":"https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl"}]}`,
			expected:    `{"files":[{"url":"/api/v1/dependency-proxy/550e8400-e29b-41d4-a716-446655440000/pypi/packages/ab/cd/requests-2.31.0-py3-none-any.whl"}]}`,
		},
		{
			name:        "scheme-relative and foreign host",
			path:        "/api/v1/dependency-proxy/pypi/simple/requests/",
			contentType: "text/html",
			upstream:    `<a href="//files.pythonhosted.org/packages/ab/cd/a.whl">a</a><a href="https://evil.example/b.whl">b</a>`,
			expected:    `<a href="/api/v1/dependency-proxy/pypi/packages/ab/cd/a.whl">a</a><a href="/api/v1/dependency-proxy/pypi/b.whl">b</a>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("package")
			c.SetParamValues("requests")

			checker := mocks.NewMaliciousPackageChecker(t)
			checker.EXPECT().GetMaliciousComponents(mock.Anything, "pypi", "requests").Return(nil, nil)

			ctrl := &PythonDependencyProxyController{
				DependencyProxyController: &DependencyProxyController{
					maliciousChecker: checker,
					client:           &http.Client{Transport: simpleIndexTransport{contentType: tc.contentType, body: tc.upstream}},
				},
			}
			if err := ctrl.ProxyPyPISimple(c); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := rec.Body.String(); got != tc.expected {
				t.Fatalf("expected body %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestProxyPyPISimpleBlocksMaliciousBeforeUpstreamFetch(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dependency-proxy/pypi/simple/fake-malicious-pypi-package/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("package")
	c.SetParamValues("fake-malicious-pypi-package")

	checker := mocks.NewMaliciousPackageChecker(t)
	checker.EXPECT().GetMaliciousComponents(mock.Anything, "pypi", "fake-malicious-pypi-package").Return([]models.MaliciousAffectedComponent{{MaliciousPackageID: "MAL-1"}}, nil)
	checker.EXPECT().GetMaliciousPackage(mock.Anything, "MAL-1").Return(models.MaliciousPackage{}, nil)

	ctrl := &PythonDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{
			maliciousChecker: checker,
			client:           &http.Client{Transport: simpleIndexTransport{}},
		},
	}

	if err := ctrl.ProxyPyPISimple(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestProxyPyPIPackageFailsClosedOnMaliciousCheckError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dependency-proxy/pypi/packages/ab/cd/requests-2.32.3.tar.gz/", nil)
	c := e.NewContext(req, httptest.NewRecorder())

	checker := mocks.NewMaliciousPackageChecker(t)
	checker.EXPECT().GetMaliciousComponents(mock.Anything, "pypi", "requests").Return(nil, errors.New("db down"))

	ctrl := &PythonDependencyProxyController{
		DependencyProxyController: &DependencyProxyController{
			maliciousChecker: checker,
			cache:            newCache(t.TempDir(), 10),
			client:           &http.Client{Transport: simpleIndexTransport{}},
		},
	}

	err := ctrl.ProxyPyPIPackage(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok || httpErr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 HTTP error, got %v", err)
	}
}

type pypiFileTransport struct {
	uploadTime time.Time
}

func (p pypiFileTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := "sdist"
	if req.URL.Path == "/pypi/requests/json" {
		if p.uploadTime.IsZero() {
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody}, nil
		}
		body = fmt.Sprintf(`{"releases":{"2.32.3":[{"upload_time_iso_8601":%q}]}}`, p.uploadTime.Format(time.RFC3339Nano))
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestProxyPyPIPackageMinReleaseAge(t *testing.T) {
	cases := []struct {
		name       string
		uploadTime time.Time
		expected   int
	}{
		{"blocks release younger than min age", time.Now().Add(-time.Hour), http.StatusForbidden},
		{"allows release older than min age", time.Now().Add(-100 * time.Hour), http.StatusOK},
		{"blocks unknown release time", time.Time{}, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret, assetID := uuid.New(), uuid.New()
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/dependency-proxy/"+secret.String()+"/pypi/packages/ab/cd/requests-2.32.3.tar.gz/", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("secret")
			c.SetParamValues(secret.String())

			proxyService := mocks.NewDependencyProxySecretService(t)
			proxyService.EXPECT().GetModelBySecret(mock.Anything, secret).Return("asset", assetID, nil)
			assetRepository := mocks.NewAssetRepository(t)
			assetRepository.EXPECT().Read(mock.Anything, mock.Anything, assetID).Return(models.Asset{ConfigFiles: databasetypes.JSONB{"dependency-proxy-configs": `{"minReleaseAge":60}`}}, nil)
			checker := mocks.NewMaliciousPackageChecker(t)
			checker.EXPECT().GetMaliciousComponents(mock.Anything, "pypi", "requests").Return(nil, nil)

			ctrl := &PythonDependencyProxyController{
				DependencyProxyController: &DependencyProxyController{
					dependencyProxyService: proxyService,
					assetRepository:        assetRepository,
					maliciousChecker:       checker,
					cache:                  newCache(t.TempDir(), 10),
					client:                 &http.Client{Transport: pypiFileTransport{uploadTime: tc.uploadTime}},
				},
			}

			if err := ctrl.ProxyPyPIPackage(c); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rec.Code != tc.expected {
				t.Fatalf("expected status %d, got %d", tc.expected, rec.Code)
			}
		})
	}
}
