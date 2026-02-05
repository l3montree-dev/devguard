package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEPSSMirrorUpdatesCVE(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Insert a CVE into the database
		cve := models.CVE{
			CVE:  "CVE-2024-0001",
			CVSS: 7.5,
		}
		require.NoError(t, f.DB.Create(&cve).Error)

		// Serve a gzipped EPSS CSV via httptest
		csvData := "model_version:v2025.01.01,score_date:2025-01-01\ncve,epss,percentile\nCVE-2024-0001,0.04250,0.91000\n"
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, err := gz.Write([]byte(csvData))
		require.NoError(t, err)
		require.NoError(t, gz.Close())
		gzBytes := buf.Bytes()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(gzBytes) // nolint
		}))
		defer srv.Close()

		// Override the URL
		origURL := vulndb.EpssURL
		vulndb.EpssURL = srv.URL
		defer func() { vulndb.EpssURL = origURL }()

		// Use a mock relationship repo that returns empty (no relationships to propagate)
		relRepo := mocks.NewCVERelationshipRepository(t)
		relRepo.On("GetRelationshipsByTargetCVEBatch", mock.Anything, mock.Anything).
			Return([]models.CVERelationship{}, nil)

		epssService := vulndb.NewEPSSService(f.App.CveRepository, relRepo)
		require.NoError(t, epssService.Mirror())

		// Verify the CVE was updated
		var updated models.CVE
		require.NoError(t, f.DB.Where("cve = ?", "CVE-2024-0001").First(&updated).Error)

		require.NotNil(t, updated.EPSS)
		assert.InDelta(t, 0.0425, *updated.EPSS, 0.0001)
		require.NotNil(t, updated.Percentile)
		assert.InDelta(t, 0.91, float64(*updated.Percentile), 0.001)
	})
}

func TestCISAKEVMirrorUpdatesCVE(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Insert a CVE into the database
		cve := models.CVE{
			CVE:  "CVE-2024-0002",
			CVSS: 9.8,
		}
		require.NoError(t, f.DB.Create(&cve).Error)

		// Serve a CISA KEV JSON via httptest
		catalog := map[string]any{
			"title":          "Test",
			"catalogVersion": "1",
			"dateReleased":   "2025-01-01",
			"count":          1,
			"vulnerabilities": []map[string]any{
				{
					"cveID":                      "CVE-2024-0002",
					"vendorProject":              "TestVendor",
					"product":                    "TestProduct",
					"vulnerabilityName":          "TestVendor TestProduct Test Vuln",
					"dateAdded":                  "2025-01-15",
					"shortDescription":           "A test vulnerability",
					"requiredAction":             "Apply updates per vendor instructions.",
					"dueDate":                    "2025-02-15",
					"knownRansomwareCampaignUse": "Unknown",
					"notes":                      "",
					"cwes":                       []string{},
				},
			},
		}
		catalogJSON, err := json.Marshal(catalog)
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(catalogJSON) // nolint
		}))
		defer srv.Close()

		// Override the URL
		origURL := vulndb.CisaKEVURL
		vulndb.CisaKEVURL = srv.URL
		defer func() { vulndb.CisaKEVURL = origURL }()

		// Use a mock relationship repo that returns empty
		relRepo := mocks.NewCVERelationshipRepository(t)
		relRepo.On("GetRelationshipsByTargetCVEBatch", mock.Anything, mock.Anything).
			Return([]models.CVERelationship{}, nil)

		kevService := vulndb.NewCISAKEVService(f.App.CveRepository, relRepo)
		require.NoError(t, kevService.Mirror())

		// Verify the CVE was updated
		var updated models.CVE
		require.NoError(t, f.DB.Where("cve = ?", "CVE-2024-0002").First(&updated).Error)

		assert.NotNil(t, updated.CISAExploitAdd)
		assert.NotNil(t, updated.CISAActionDue)
		assert.Equal(t, "Apply updates per vendor instructions.", updated.CISARequiredAction)
		assert.Equal(t, "TestVendor TestProduct Test Vuln", updated.CISAVulnerabilityName)
	})
}
