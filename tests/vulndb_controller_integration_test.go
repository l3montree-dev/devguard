package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCVEEcosystemDistribution(t *testing.T) {
	t.Parallel()
	db, pool, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	app, _ := NewTestAppWithT(t, db, pool, nil)

	// two CVEs sharing one golang component and one CVE in an npm component
	cveA := models.CVE{CVE: "CVE-2026-11111", DatePublished: time.Now(), DateLastModified: time.Now()}
	cveB := models.CVE{CVE: "CVE-2026-22222", DatePublished: time.Now(), DateLastModified: time.Now()}
	cveC := models.CVE{CVE: "CVE-2026-33333", DatePublished: time.Now(), DateLastModified: time.Now()}
	require.NoError(t, db.Create(&[]models.CVE{cveA, cveB, cveC}).Error)

	golangComponent := models.AffectedComponent{
		Ecosystem: "Golang",
		CVE:       []models.CVE{cveA, cveB},
	}
	npmComponent := models.AffectedComponent{
		Ecosystem: "npm",
		CVE:       []models.CVE{cveC},
	}
	require.NoError(t, db.Create(&golangComponent).Error)
	require.NoError(t, db.Create(&npmComponent).Error)

	// one malicious npm package
	maliciousPackage := models.MaliciousPackage{ID: "MAL-2026-0001"}
	require.NoError(t, db.Create(&maliciousPackage).Error)
	require.NoError(t, db.Create(&models.MaliciousAffectedComponent{
		MaliciousPackageID: maliciousPackage.ID,
		Ecosystem:          "npm",
	}).Error)

	callEndpoint := func() map[string]int {
		rec := httptest.NewRecorder()
		ctx := NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		require.NoError(t, app.VulnDBController.GetCVEEcosystemDistribution(ctx))
		require.Equal(t, http.StatusOK, rec.Code)

		var body map[string]int
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}

	t.Run("computes the distribution per ecosystem", func(t *testing.T) {
		// 2 distinct CVEs in golang (lowercased), 1 CVE + 1 malicious package in npm
		assert.Equal(t, map[string]int{"golang": 2, "npm": 2}, callEndpoint())
	})

	t.Run("serves the cached value on subsequent calls", func(t *testing.T) {
		newComponent := models.AffectedComponent{
			Ecosystem: "pypi",
			CVE:       []models.CVE{cveA},
		}
		require.NoError(t, db.Create(&newComponent).Error)

		// the new pypi component must not show up yet - the first call cached the result
		assert.Equal(t, map[string]int{"golang": 2, "npm": 2}, callEndpoint())
	})
}
