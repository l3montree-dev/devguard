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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	databasetypes "github.com/l3montree-dev/devguard/database/types"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

// newMinReleaseAgeController builds a proxy controller whose configs resolve to
// the given MinReleaseAge (in hours) for any request carrying the proxy secret.
func newMinReleaseAgeController(t *testing.T, minReleaseAge int) (*DependencyProxyController, uuid.UUID) {
	t.Helper()

	secret := uuid.New()
	assetID := uuid.New()

	secretService := mocks.NewDependencyProxySecretService(t)
	secretService.EXPECT().GetModelBySecret(mock.Anything, secret).Return("asset", assetID, nil).Maybe()

	assetRepository := mocks.NewAssetRepository(t)
	assetRepository.EXPECT().Read(mock.Anything, mock.Anything, assetID).Return(models.Asset{
		ConfigFiles: databasetypes.JSONB{
			"dependency-proxy-configs": fmt.Sprintf(`{"rules":"","minReleaseAge":%d}`, minReleaseAge),
		},
	}, nil).Maybe()

	maliciousChecker := mocks.NewMaliciousPackageChecker(t)
	maliciousChecker.EXPECT().GetMaliciousComponents(mock.Anything, mock.Anything, mock.Anything).
		Return([]models.MaliciousAffectedComponent{}, nil).Maybe()

	return &DependencyProxyController{
		dependencyProxyService: secretService,
		assetRepository:        assetRepository,
		maliciousChecker:       maliciousChecker,
		cache:                  newCache(t.TempDir(), 10),
		client:                 http.DefaultClient,
	}, secret
}

// newProxyRequest builds an echo context for a proxy request that carries the secret.
func newProxyRequest(secret uuid.UUID, path string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("secret")
	c.SetParamValues(secret.String())
	return c, rec
}

func TestNPMMinReleaseAgeOnCacheHit(t *testing.T) {
	cases := []struct {
		name           string
		releaseAge     time.Duration
		expectedStatus int
		expectBlocked  bool
	}{
		{
			name:           "blocks package younger than the minimum release age",
			releaseAge:     1 * time.Hour,
			expectedStatus: http.StatusForbidden,
			expectBlocked:  true,
		},
		{
			name:           "serves package older than the minimum release age",
			releaseAge:     48 * time.Hour,
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, secret := newMinReleaseAgeController(t, 24)
			controller := NewNPMDependencyProxyController(d)

			requestPath := "/lodash/-/lodash-4.17.21.tgz"
			if err := d.cache.Set("npm/tarball"+requestPath, cacheValue{
				data:        []byte("tarball"),
				releaseTime: time.Now().Add(-tc.releaseAge),
			}); err != nil {
				t.Fatalf("failed to seed cache: %v", err)
			}

			c, rec := newProxyRequest(secret, "/api/v1/dependency-proxy/"+secret.String()+"/npm"+requestPath)

			if err := controller.ProxyNPMTarball(c); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			assertTooNewBlocked(t, rec, tc.expectedStatus, tc.expectBlocked)
		})
	}
}

func TestGoMinReleaseAgeOnCacheHit(t *testing.T) {
	cases := []struct {
		name           string
		releaseAge     time.Duration
		expectedStatus int
		expectBlocked  bool
	}{
		{
			name:           "blocks module younger than the minimum release age",
			releaseAge:     30 * time.Minute,
			expectedStatus: http.StatusForbidden,
			expectBlocked:  true,
		},
		{
			name:           "serves module older than the minimum release age",
			releaseAge:     72 * time.Hour,
			expectedStatus: http.StatusOK,
			expectBlocked:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, secret := newMinReleaseAgeController(t, 24)
			controller := NewGoDependencyProxyController(d)

			requestPath := "github.com/foo/bar/@v/v1.2.3.info"
			if err := d.cache.Set("go/"+requestPath, cacheValue{
				data:        []byte(`{"Version":"v1.2.3"}`),
				releaseTime: time.Now().Add(-tc.releaseAge),
			}); err != nil {
				t.Fatalf("failed to seed cache: %v", err)
			}

			c, rec := newProxyRequest(secret, "/api/v1/dependency-proxy/"+secret.String()+"/go/"+requestPath)

			if err := controller.ProxyGo(c); err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			assertTooNewBlocked(t, rec, tc.expectedStatus, tc.expectBlocked)
		})
	}
}

func assertTooNewBlocked(t *testing.T, rec *httptest.ResponseRecorder, expectedStatus int, expectBlocked bool) {
	t.Helper()

	if rec.Code != expectedStatus {
		t.Fatalf("expected status %d, got %d (body: %s)", expectedStatus, rec.Code, rec.Body.String())
	}

	blocked := rec.Header().Get("X-Too-New-Package") == "blocked"
	if blocked != expectBlocked {
		t.Fatalf("expected blocked=%v, got blocked=%v (body: %s)", expectBlocked, blocked, rec.Body.String())
	}
}
