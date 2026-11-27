package tests

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataTransferRoundtrip(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		t.Run("export devguard state and import into empty database should result in no error and identical database states", func(t *testing.T) {
			f.T = t
			exportOrg, err := f.CreateTestData()
			require.NoError(t, err)
			exportRec := httptest.NewRecorder()
			exportApp := echo.New()
			exportReq := httptest.NewRequest("GET", fmt.Sprintf("/organizations/%s/export", exportOrg.Slug), nil)
			exportCTX := exportApp.NewContext(exportReq, exportRec)
			shared.SetOrg(exportCTX, exportOrg)
			require.NoError(t, f.App.OrgController.ExportOrg(exportCTX))

			// calculate the content hash of the database before importing
			exportStateHash, err := f.calculateDatabaseContentHash(exportReq.Context())
			require.NoError(t, err)

			slog.Info("finished database export, start re-importing file into database")

			f.ResetDatabase() // reset the database to avoid collision/conflicts due to existing data

			importCTX := context.Background()

			testUserID := uuid.New().String()
			importOptions := dtos.DataTransferImportOptions{
				EntityType: dtos.DataTransferEntityOrg,
				OwnerID:    testUserID,
			}
			require.NoError(t, f.App.DataTransferService.ImportFile(importCTX, exportRec.Body, importOptions))
			// calculate the hash again after a successful import
			importStateHash, err := f.calculateDatabaseContentHash(importCTX)
			require.NoError(t, err)

			// both database states should be identical
			assert.Equal(t, exportStateHash, importStateHash, "state after import should match the state of the exported database")

			// check RBAC
		})
	})
}

// cves are not exported, so the import side has to re-create this cve before importing
const dataTransferTestCVEID = "CVE-2026-0001"

// creates at least one row in every table of services.TablesToSync, all reachable from the returned org
func (f *TestFixture) CreateTestData() (models.Org, error) {
	org, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

	// fills artifacts, sboms, sbom_merkle_nodes and sbom_merkle_edges
	if err := SeedDirectDependencies(f.DB, assetVersion, "test-artifact", "pkg:npm/test-component@1.0.0"); err != nil {
		return org, err
	}
	var artifact models.Artifact
	if err := f.DB.Where("asset_version_id = ? AND artifact_name = ?", assetVersion.ID, "test-artifact").First(&artifact).Error; err != nil {
		return org, err
	}

	projectKey := "github.com/test/test-component"
	componentProject := models.ComponentProject{ProjectKey: projectKey, License: "MIT"}
	if err := f.DB.Create(&componentProject).Error; err != nil {
		return org, err
	}
	component := models.Component{ID: "pkg:npm/test-component@1.0.0", ComponentType: dtos.ComponentTypeLibrary, ComponentProjectKey: &projectKey}
	if err := f.DB.Create(&component).Error; err != nil {
		return org, err
	}

	if err := f.DB.Create(&models.CVE{CVE: dataTransferTestCVEID}).Error; err != nil {
		return org, err
	}

	externalUser := models.ExternalUser{ID: "test-external-user", Username: "test-user", Organizations: []models.Org{org}}
	if err := f.DB.Create(&externalUser).Error; err != nil {
		return org, err
	}

	frameworkControl := models.FrameworkControl{Framework: "test-framework", ControlID: "control-1", Title: "Test Control"}
	if err := f.DB.Create(&frameworkControl).Error; err != nil {
		return org, err
	}
	compliancePosture := models.CompliancePosture{FrameworkControlID: frameworkControl.FrameworkControlID, OrgID: org.ID}
	// BeforeSave has a value receiver, so the hook does not persist the id
	compliancePosture.ID = compliancePosture.CalculateHash()
	if err := f.DB.Create(&compliancePosture).Error; err != nil {
		return org, err
	}

	externalReference := models.ExternalReference{AssetID: asset.ID, URL: "https://example.com/vex.json", Type: dtos.ExternalReferenceTypeOpenVEX}
	if err := f.DB.Create(&externalReference).Error; err != nil {
		return org, err
	}

	vexRule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{VexSource: "test", Title: "Test Rule", Justification: "not_affected", EventType: dtos.EventTypeFalsePositive, CELExpression: "true"},
		AssetID:         asset.ID,
		CreatedByID:     "test-user",
		Enabled:         true,
	}
	vexRule.EnsureID()
	if err := f.DB.Create(&vexRule).Error; err != nil {
		return org, err
	}

	attestation := models.Attestation{PredicateType: "https://slsa.dev/provenance/v1", ArtifactID: artifact.ID, AssetID: asset.ID}
	if err := f.DB.Create(&attestation).Error; err != nil {
		return org, err
	}

	vulnerability := models.Vulnerability{AssetVersionID: assetVersion.ID, AssetID: asset.ID, State: dtos.VulnStateOpen}

	// the artifacts field also fills the artifact_dependency_vulns pivot table
	dependencyVuln := models.DependencyVuln{
		Vulnerability:     vulnerability,
		AssetVersionName:  assetVersion.Name,
		CVEID:             dataTransferTestCVEID,
		ComponentPurl:     component.ID,
		VulnerabilityPath: []string{component.ID},
		Artifacts:         []models.Artifact{artifact},
	}
	if err := f.DB.Create(&dependencyVuln).Error; err != nil {
		return org, err
	}

	// the artifacts field also fills the artifact_license_risks pivot table
	licenseRisk := models.LicenseRisk{Vulnerability: vulnerability, AssetVersionName: assetVersion.Name, ComponentPurl: component.ID, Artifacts: []models.Artifact{artifact}}
	if err := f.DB.Create(&licenseRisk).Error; err != nil {
		return org, err
	}

	firstPartyVuln := models.FirstPartyVuln{Vulnerability: vulnerability, AssetVersionName: assetVersion.Name, ScannerIDs: "test-scanner", RuleID: "test-rule"}
	if err := f.DB.Create(&firstPartyVuln).Error; err != nil {
		return org, err
	}

	advisory := models.Advisory{Vulnerability: vulnerability, Title: "Test Advisory", Severity: "high"}
	if err := f.DB.Create(&advisory).Error; err != nil {
		return org, err
	}

	// one event per parent so every vuln_events filter of the export is covered
	vulnEvents := []models.VulnEvent{
		{Type: dtos.EventTypeDetected, UserID: "system", DependencyVulnID: &dependencyVuln.ID},
		{Type: dtos.EventTypeDetected, UserID: "system", LicenseRiskID: &licenseRisk.ID},
		{Type: dtos.EventTypeDetected, UserID: "system", FirstPartyVulnID: &firstPartyVuln.ID},
		{Type: dtos.EventTypeDetected, UserID: "system", CompliancePostureID: &compliancePosture.ID},
		{Type: dtos.EventTypeDetected, UserID: "system", SecurityAdvisoryID: &advisory.ID},
	}
	if err := f.DB.Create(&vulnEvents).Error; err != nil {
		return org, err
	}

	return org, nil
}

// calculate the content hash for all tables synced by the export/import
func (f *TestFixture) calculateDatabaseContentHash(ctx context.Context) (string, error) {
	tx, err := f.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer tx.Commit(ctx) // nolint

	hash := ""
	// map iteration and row order are not deterministic, so sort both to get a stable hash
	for _, table := range slices.Sorted(maps.Keys(services.TablesToSync)) {
		err := func() error {
			sql := fmt.Sprintf("SELECT row_to_json(t)::text FROM public.%s t ORDER BY 1", table)
			rows, err := tx.Query(ctx, sql)
			if err != nil {
				return err
			}
			defer rows.Close()

			rowsForTable := make([]byte, 0, 1000)
			for rows.Next() {
				var row []byte
				err = rows.Scan(&row)
				if err != nil {
					return err
				}
				rowsForTable = append(rowsForTable, row...)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			sum := md5.Sum(rowsForTable)
			hash += hex.EncodeToString(sum[:])

			return nil
		}()
		if err != nil {
			return "", err
		}
	}
	return hash, nil
}

// every table of the migrated schema is listed in exactly one of the two lists, so a new table fails this test and cannot be silently missed by the data transfer export
var dataTransferExportedTables = []string{
	"advisories",
	"artifact_dependency_vulns",
	"artifact_license_risks",
	"artifacts",
	"asset_versions",
	"assets",
	"attestations",
	"compliance_postures",
	"component_projects",
	"components",
	"dependency_vulns",
	"external_references",
	"external_user_orgs",
	"external_users",
	"first_party_vulnerabilities",
	"frameworks_controls",
	"license_risks",
	"organizations",
	"projects",
	"sbom_merkle_edges",
	"sbom_merkle_nodes",
	"sboms",
	"vex_rules",
	"vuln_events",
}

var dataTransferNotExportedTables = []string{
	"access_tokens",
	"advisories_affected_packages",
	"affected_components",
	"affected_packages",
	"artifact_risk_history",
	"asset_risk_history",
	"casbin_rule",
	"compliance_component_implements_control_statements",
	"compliance_component_implements_controls",
	"compliance_components",
	"component_dependencies",
	"config",
	"cve_affected_component",
	"cve_relationships",
	"cves",
	"cwes",
	"dependency_proxy_secrets",
	"exploits",
	"github_app_installations",
	"gitlab_integrations",
	"gitlab_oauth2_tokens",
	"in_toto_links",
	"invitations",
	"jira_integrations",
	"license_overwrite",
	"logs",
	"malicious_affected_components",
	"malicious_packages",
	"mapped_controls",
	"policies",
	"project_enabled_policies",
	"project_risk_history",
	"release_items",
	"releases",
	"schema_migrations",
	"supply_chain",
	"trusted_entities",
	"upstream_vex_rules",
	"vex_rule_recommendations",
	"vuln_state_intervals",
	"weaknesses",
	"webhook_integrations",
}

// called from TestRunMigrations to reuse its migrated database instead of starting another container
func assertDatabaseTablesMatchExpectedTables(t *testing.T, db shared.DB) {
	t.Helper()
	var tables []string
	err := db.Raw(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`).Scan(&tables).Error
	require.NoError(t, err)

	expectedTables := slices.Concat(dataTransferExportedTables, dataTransferNotExportedTables)
	assert.ElementsMatch(t, expectedTables, tables, "the database tables changed, most likely a new table has been added. For that table decide whether it needs to be exported along side the existent tables in data_transfer_service.go or if the export logic changed in anyway.")
}
