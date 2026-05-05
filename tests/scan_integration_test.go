package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"go.uber.org/fx"
	"gorm.io/gorm/clause"
)

// Helper to extract artifact names from []models.Artifact
func getArtifactNames(artifacts []dtos.ArtifactDTO) []string {
	names := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		names = append(names, a.ArtifactName)
	}
	return names
}

func TestMultipleOrigins(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should close vulnerability for specific origin", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "origin-1")           // set the origin header
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 1, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 1)
			assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)
			assert.Len(t, response.DependencyVulns[0].Artifacts, 1)

			// Scan again with same origin but empty SBOM to close the vulnerability for that origin
			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()

			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "origin-1")           // set the same origin header
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 1, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)
		})

		t.Run("should not close vulnerability for different origin", func(t *testing.T) {

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "origin-1")           // set the origin header
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 1, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 1)
			assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)
			assert.Len(t, response.DependencyVulns[0].Artifacts, 1)

			// Scan again with same origin but empty SBOM to close the vulnerability for that origin
			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()

			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "origin-2")           // set a different origin header
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 1)
			assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)
			assert.Len(t, response.DependencyVulns[0].Artifacts, 1)

		})

	})
}

func TestKeepExistingVulnsClosed(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}
		t.Run("should close the vulnerability if it's not detected anymore for the same artifact and origin and stay closed when the asset daemon is run", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "test-origin")        // set the origin header
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse

			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 1, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 1)
			assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)

			// Scan again with other SBOM without the vulnerability, but with the same artifact and origin - should close the vulnerability

			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()

			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "test-origin")        // set the same origin header
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)

			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 1, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)

			//start the asset daemon and make sure the vulnerability is still closed

			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)

			// Reload the vulnerability from the database to check its state
			var vulns []models.DependencyVuln
			err = f.DB.Where("asset_id = ?", asset.ID).Find(&vulns).Error
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			assert.Equal(t, dtos.VulnStateFixed, vulns[0].State)
			assert.Equal(t, "CVE-2025-46569", vulns[0].CVEID)
		})

		t.Run("scanning empty sbom on a different branch should not change the vuln state on the original branch", func(t *testing.T) {
			// First scan with vulnerability on main branch
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "test-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 1, response.AmountOpened)

			// Now scan an empty SBOM on a different branch — should NOT close the main branch vuln
			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "feature-branch") // different branch
			req.Header.Set("X-Origin", "test-origin")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)

			// Verify the main branch vuln is still open
			var vulns []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND asset_version_name = ?", asset.ID, "main").Find(&vulns).Error
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			assert.Equal(t, dtos.VulnStateOpen, vulns[0].State)
			assert.Equal(t, "CVE-2025-46569", vulns[0].CVEID)
		})

		t.Run("scanning empty sbom on a different artifact should not change the vuln state on the original artifact", func(t *testing.T) {
			// First scan with vulnerability on artifact-multi-1
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-multi-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "test-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Confirm the vuln is open (may have been opened by a previous sub-test already)
			var vulnsAfterFirst []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, "main", "CVE-2025-46569").Find(&vulnsAfterFirst).Error
			assert.Nil(t, err)
			assert.Len(t, vulnsAfterFirst, 1)
			assert.Equal(t, dtos.VulnStateOpen, vulnsAfterFirst[0].State)

			// Now scan an empty SBOM on a different artifact — should NOT close the vuln from artifact-multi-1
			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-multi-2") // different artifact
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "test-origin")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Verify the vuln is still open (artifact-multi-1 still has it)
			var vulns []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, "main", "CVE-2025-46569").Find(&vulns).Error
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			assert.Equal(t, dtos.VulnStateOpen, vulns[0].State)
		})

		t.Run("a fixed event should NOT reopen a vulnerability marked as false positive", func(t *testing.T) {
			// Step 1: scan with vulnerability on main / artifact-fp-1
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-fp-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "test-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Step 2: mark the vulnerability as false positive
			var vulns []models.DependencyVuln
			err = f.DB.Where("asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, "main", "CVE-2025-46569").Find(&vulns).Error
			assert.Nil(t, err)

			var fpVuln *models.DependencyVuln
			for i := range vulns {
				if vulns[i].CVEID == "CVE-2025-46569" {
					fpVuln = &vulns[i]
					break
				}
			}
			assert.NotNil(t, fpVuln, "should have found the vuln to mark as false positive")

			dependencyVulnRepository := f.App.DependencyVulnRepository
			fpEvent := models.NewFalsePositiveEvent(fpVuln.ID, fpVuln.GetType(), "abc", "this is a false positive", "", "artifact-fp-1", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, fpVuln, &fpEvent)
			assert.Nil(t, err)

			// Confirm it's now marked as false positive
			err = f.DB.First(fpVuln, "id = ?", fpVuln.ID).Error
			assert.Nil(t, err)
			assert.Equal(t, dtos.VulnStateFalsePositive, fpVuln.State)

			// Step 3: scan empty SBOM on same artifact and branch — this would trigger a "fixed" event
			recorder = httptest.NewRecorder()
			emptySbomFile := emptySbom()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", emptySbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-fp-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "test-origin")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Step 4: verify the false positive state is preserved — NOT reopened
			err = f.DB.First(fpVuln, "id = ?", fpVuln.ID).Error
			assert.Nil(t, err)
			assert.Equal(t, dtos.VulnStateFalsePositive, fpVuln.State, "false positive should not be overridden by a fixed event")
		})
	})
}

// TestUserAssessmentLifecycle covers every realistic combination of user assessments
// (falsePositive, accepted) interleaved with scan events (component present / absent)
// across single and multiple artifacts.  Each sub-test is self-contained via a fresh
// WithTestApp so there is no shared state between scenarios.
func TestUserAssessmentLifecycle(t *testing.T) {
	// ── helpers ──────────────────────────────────────────────────────────────────
	scan := func(t *testing.T, controller interface{ ScanDependencyVulnFromProject(shared.Context) error }, app *echo.Echo, setupCtx func(shared.Context), artifactName, ref, defaultBranch string, sbomBody func() io.Reader) {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomBody())
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", artifactName)
		req.Header.Set("X-Asset-Default-Branch", defaultBranch)
		req.Header.Set("X-Asset-Ref", ref)
		req.Header.Set("X-Origin", "test-origin")
		ctx := app.NewContext(req, recorder)
		setupCtx(ctx)
		assert.Nil(t, controller.ScanDependencyVulnFromProject(ctx))
		assert.Equal(t, 200, recorder.Code)
	}

	loadVuln := func(t *testing.T, db shared.DB, assetID interface{}, branch string) *models.DependencyVuln {
		t.Helper()
		var vulns []models.DependencyVuln
		assert.Nil(t, db.Where("asset_id = ? AND asset_version_name = ? AND cve_id = ?", assetID, branch, "CVE-2025-46569").Find(&vulns).Error)
		if len(vulns) == 0 {
			return nil
		}
		return &vulns[0]
	}

	markFP := func(t *testing.T, repo shared.DependencyVulnRepository, vuln *models.DependencyVuln, artifact string) {
		t.Helper()
		ev := models.NewFalsePositiveEvent(vuln.ID, vuln.GetType(), "user-abc", "false positive", "", artifact, false)
		assert.Nil(t, repo.ApplyAndSave(context.Background(), nil, vuln, &ev))
	}

	markAccepted := func(t *testing.T, repo shared.DependencyVulnRepository, vuln *models.DependencyVuln) {
		t.Helper()
		ev := models.NewAcceptedEvent(vuln.ID, vuln.GetType(), "user-abc", "accepted", false)
		assert.Nil(t, repo.ApplyAndSave(context.Background(), nil, vuln, &ev))
	}

	reload := func(t *testing.T, db shared.DB, vuln *models.DependencyVuln) {
		t.Helper()
		assert.Nil(t, db.First(vuln, "id = ?", vuln.ID).Error)
	}

	// ── scenario 1 ───────────────────────────────────────────────────────────────
	// open → falsePositive → component gone (fixed) → component back → must reopen with a reopened event
	t.Run("falsePositive: component gone then back must reopen with event", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			assert.Equal(t, dtos.VulnStateOpen, vuln.State)

			markFP(t, repo, vuln, "art")
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)

			// component disappears
			scan(t, ctrl, app, setupCtx, "art", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFixed, vuln.State, "component gone: falsePositive→fixed is expected")

			// component comes back — must fire a reopened event and be open (not silently reset via detected)
			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateOpen, vuln.State, "component returned: expected reopened event → open")
		})
	})

	// ── scenario 2 ───────────────────────────────────────────────────────────────
	// open → accepted → component gone (fixed) → component back → must reopen with a reopened event
	t.Run("accepted: component gone then back must reopen with event", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markAccepted(t, repo, vuln)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateAccepted, vuln.State)

			scan(t, ctrl, app, setupCtx, "art", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFixed, vuln.State, "component gone: accepted→fixed is expected")

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateOpen, vuln.State, "component returned: expected reopened event → open")
		})
	})

	// ── scenario 3 ───────────────────────────────────────────────────────────────
	// open → falsePositive → component gone → component back → multiple repeated cycles
	t.Run("falsePositive: multiple fix/reappear cycles must reopen with event", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markFP(t, repo, vuln, "art")

			for i := 0; i < 3; i++ {
				scan(t, ctrl, app, setupCtx, "art", "main", "main", emptySbom) // gone
				f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
				scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability) // back
				f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
				reload(t, f.DB, vuln)
				assert.Equal(t, dtos.VulnStateOpen, vuln.State, "cycle %d: component returned, expected reopened event → open", i+1)
			}
		})
	})

	// ── scenario 4 ───────────────────────────────────────────────────────────────
	// open → falsePositive, then a DIFFERENT artifact scans empty — must not affect this vuln
	t.Run("falsePositive: empty scan on different artifact must not affect state", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art-a", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markFP(t, repo, vuln, "art-a")

			// different artifact scans empty
			scan(t, ctrl, app, setupCtx, "art-b", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State, "BUG: empty scan on art-b changed state of art-a's vuln")
		})
	})

	// ── scenario 5 ───────────────────────────────────────────────────────────────
	// open → falsePositive, then a DIFFERENT branch scans empty — must not affect this vuln
	t.Run("falsePositive: empty scan on different branch must not affect state", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markFP(t, repo, vuln, "art")

			// different branch scans empty
			scan(t, ctrl, app, setupCtx, "art", "feature-branch", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State, "BUG: empty scan on feature-branch changed state of main's vuln")
		})
	})

	// ── scenario 6 ───────────────────────────────────────────────────────────────
	// two artifacts both have the vuln → user marks FP → one artifact goes empty → other still present
	// vuln must stay falsePositive (not fixed, not open)
	t.Run("falsePositive: one of two artifacts goes empty must not close vuln", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art-a", "main", "main", sbomWithVulnerability)
			scan(t, ctrl, app, setupCtx, "art-b", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			assert.Equal(t, dtos.VulnStateOpen, vuln.State)

			markFP(t, repo, vuln, "art-a")
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)

			// art-a goes empty; art-b still has the vuln
			scan(t, ctrl, app, setupCtx, "art-a", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State, "BUG: vuln changed state when only one of two artifacts went empty")

			// now art-b also goes empty — now it should be fixed
			scan(t, ctrl, app, setupCtx, "art-b", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFixed, vuln.State, "both artifacts empty: vuln should be fixed")
		})
	})

	// ── scenario 7 ───────────────────────────────────────────────────────────────
	// open → falsePositive → daemon re-scan (component still present in stored SBOM) → must not reopen
	t.Run("falsePositive: daemon rescan with component present must not reopen", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markFP(t, repo, vuln, "art")
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)

			// daemon rescans with the same (vulnerable) SBOM
			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.NotEqual(t, dtos.VulnStateOpen, vuln.State, "BUG: falsePositive vuln reopened by daemon rescan")
		})
	})

	// ── scenario 8 ───────────────────────────────────────────────────────────────
	// accepted → daemon rescan (component still present) → must not reopen
	t.Run("accepted: daemon rescan with component present must not reopen", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			markAccepted(t, repo, vuln)

			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.NotEqual(t, dtos.VulnStateOpen, vuln.State, "BUG: accepted vuln reopened by daemon rescan")
		})
	})

	// ── scenario 9 ───────────────────────────────────────────────────────────────
	// Production event stream pattern:
	// open → FP (VEX/user) → fixed (component gone) → open (component back, BUG) → FP again → ...
	// Simulates the repeating cycle seen in production.
	t.Run("production cycle: open→FP→fixed→reopened when component returns", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			// initial detection
			scan(t, ctrl, app, setupCtx, "source", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			vuln := loadVuln(t, f.DB, asset.ID, "main")
			assert.Equal(t, dtos.VulnStateOpen, vuln.State)

			// user marks FP (because they know it's not exploitable)
			markFP(t, repo, vuln, "source")
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, vuln.State)

			// upstream SBOM momentarily doesn't have the component (network glitch, partial SBOM)
			scan(t, ctrl, app, setupCtx, "source", "main", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			stateAfterEmpty := vuln.State
			// falsePositive→fixed is allowed per user preference
			assert.NotEqual(t, dtos.VulnStateOpen, stateAfterEmpty)

			// upstream SBOM comes back with the component — must fire reopened event → open
			scan(t, ctrl, app, setupCtx, "source", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, vuln)
			assert.Equal(t, dtos.VulnStateOpen, vuln.State,
				"component returned: expected explicit reopened event → open")
		})
	})

	// ── scenario 10 ──────────────────────────────────────────────────────────────
	// open → falsePositive → scan with component present on a different branch inherits FP
	// then that branch's empty scan must not affect the main branch state
	t.Run("falsePositive: cross-branch inheritance then empty scan isolation", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			app := echo.New()
			createCVE2025_46569(f.DB)
			org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
			setupCtx := func(ctx shared.Context) {
				s := mocks.NewAuthSession(t)
				s.On("GetUserID").Return("abc")
				shared.SetAsset(ctx, asset)
				shared.SetProject(ctx, project)
				shared.SetOrg(ctx, org)
				shared.SetSession(ctx, s)
			}
			ctrl := f.App.ScanController
			repo := f.App.DependencyVulnRepository

			// establish FP on main
			scan(t, ctrl, app, setupCtx, "art", "main", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			mainVuln := loadVuln(t, f.DB, asset.ID, "main")
			markFP(t, repo, mainVuln, "art")

			// feature branch detects same vuln (inherits FP from main)
			scan(t, ctrl, app, setupCtx, "art", "feature", "main", sbomWithVulnerability)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)

			// feature branch scans empty — must NOT affect main branch vuln
			scan(t, ctrl, app, setupCtx, "art", "feature", "main", emptySbom)
			f.App.DaemonRunner.RunAssetPipeline(context.Background(), true)
			reload(t, f.DB, mainVuln)
			assert.Equal(t, dtos.VulnStateFalsePositive, mainVuln.State,
				"BUG: empty scan on feature branch changed main branch vuln state")
		})
	})
}

func TestScanning(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should find a vulnerability in the SBOM", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
			req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
			req.Header.Set("X-Origin", "test-origin")        // set the origin header
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse

			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 1, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 1)
			assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)
		})

		t.Run("should add the artifact, if the vulnerability is found with another artifact", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-2")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			// Same dependency path (filtered to PURLs only) = same vulnerability
			// artifact-2 is added to the existing vulnerability
			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)

			assert.Len(t, response.DependencyVulns, 1)

			if len(response.DependencyVulns) > 0 {
				assert.Equal(t, "CVE-2025-46569", response.DependencyVulns[0].CVEID)
				// Both artifacts now belong to the same vulnerability
				assert.ElementsMatch(t, []string{"artifact-1", "artifact-2"}, getArtifactNames(response.DependencyVulns[0].Artifacts))
			}
		})

		t.Run("should return vulnerabilities, which are found by the current artifact", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithoutVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-3")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)
		})

		t.Run("should return amount of closed 1, if the vulnerability is not detected in ANY artifact anymore", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithoutVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)
			// Vuln still exists (artifact-2 still has it), so nothing closed yet
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)

			sbomFile2 := sbomWithoutVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile2)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-2")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "main")
			recorder = httptest.NewRecorder()
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 0, response.AmountOpened)
			// Now both artifacts no longer have the vuln, so it's closed
			assert.Equal(t, 1, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)
		})

		t.Run("should respect, if the vulnerability is found AGAIN on a different branch then the default branch", func(t *testing.T) {
			// First, scan artifact-1 with the vulnerability again to re-open it
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)
			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, err := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)

			// Find the vuln on main to accept it
			var mainVuln *models.DependencyVuln
			for i := range vulns {
				if vulns[i].AssetVersionName == "main" {
					mainVuln = &vulns[i]
					break
				}
			}
			assert.NotNil(t, mainVuln, "should have a vuln on main branch")

			acceptedEvent := models.NewAcceptedEvent(mainVuln.ID, mainVuln.GetType(), "abc", "accepting the vulnerability", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, mainVuln, &acceptedEvent)
			assert.Nil(t, err)

			// Now scan on a different branch
			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Origin", "test-origin")
			req.Header.Set("X-Asset-Ref", "some-other-branch")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)

			var newVuln models.DependencyVuln
			for _, v := range vulns {
				if v.AssetVersionName == "some-other-branch" {
					newVuln = v
					break
				}
			}
			assert.NotEmpty(t, newVuln.ID, "should have a vuln on some-other-branch")

			// Reload the vulnerability with Events preloaded
			err = f.DB.Preload("Events").First(&newVuln, "id = ?", newVuln.ID).Error
			assert.Nil(t, err)

			assert.NotEmpty(t, newVuln.Events)
			// New vuln on other branch should inherit the accepted state from the main branch vuln
			// The inheritance looks up the matching vuln on the default branch by asset-version-independent hash
			// which includes the filtered vulnerability path (PURLs only)
			assert.Equal(t, dtos.VulnStateAccepted, newVuln.State)

			// Check that the accepted event was copied
			var accEvent models.VulnEvent
			for _, ev := range newVuln.Events {
				if ev.Type == dtos.EventTypeAccepted {
					accEvent = ev
					break
				}
			}

			assert.NotEmpty(t, accEvent)
			assert.Equal(t, dtos.EventTypeAccepted, accEvent.Type)
			assert.Equal(t, "accepting the vulnerability", *accEvent.Justification)
			assert.Equal(t, "main", *accEvent.OriginalAssetVersionName)
		})
	})
}

func TestVulnerabilityStateOnMultipleArtifacts(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should copy the events one time from a different branch even if the vulnerability is exiting on multiple artifacts", func(t *testing.T) {

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, _ := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			for _, vuln := range vulns {
				f.DB.Exec("DELETE FROM artifact_dependency_vulns WHERE dependency_vuln_id = ?", vuln.ID)
				f.DB.Delete(&vuln)
			}

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing state management", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			branchAVuln = vulns[0]
			assert.Equal(t, dtos.VulnStateAccepted, branchAVuln.State)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact-2")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln = vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateAccepted, branchAVuln.State)
			assert.Len(t, branchAVuln.Events, 2)

		})
	})
}

func TestVulnerabilityLifecycleManagementOnMultipleArtifacts(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should copy the events one time from a different branch even if the vulnerability is exiting on multiple artifacts", func(t *testing.T) {

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, _ := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			for _, vuln := range vulns {
				f.DB.Exec("DELETE FROM artifact_dependency_vulns WHERE dependency_vuln_id = ?", vuln.ID)
				f.DB.Delete(&vuln)
			}

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact-2")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln = vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)
			assert.Len(t, branchAVuln.Events, 1)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-b")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)
			var branchAFinalVuln, branchBVuln models.DependencyVuln
			for _, vuln := range vulns {
				switch vuln.AssetVersionName {
				case "branch-a":
					branchAFinalVuln = vuln
				case "branch-b":
					branchBVuln = vuln
				}
			}

			assert.Equal(t, "branch-a", branchAFinalVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAFinalVuln.State)
			assert.Len(t, branchAFinalVuln.Events, 1)
			assert.Equal(t, "branch-b", branchBVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchBVuln.State)
			assert.Len(t, branchBVuln.Events, 1) // only one event should be copied
		})
	})
}

func TestVulnerabilityLifecycleManagement(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should copy all events when vulnerability is found on different branches - complete lifecycle test", func(t *testing.T) {

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, _ := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			for _, vuln := range vulns {
				f.DB.Exec("DELETE FROM artifact_dependency_vulns WHERE dependency_vuln_id = ?", vuln.ID)
				f.DB.Delete(&vuln)
			}

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing lifecycle management", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "This is a test comment for lifecycle verification", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, &branchAVuln, &commentEvent)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln = vulns[0]
			assert.Equal(t, dtos.VulnStateAccepted, branchAVuln.State)
			assert.Len(t, branchAVuln.Events, 3)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-b")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)

			var branchAFinalVuln, branchBVuln models.DependencyVuln
			for _, vuln := range vulns {
				switch vuln.AssetVersionName {
				case "branch-a":
					branchAFinalVuln = vuln
				case "branch-b":
					branchBVuln = vuln
				}
			}

			assert.Equal(t, "branch-a", branchAFinalVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateAccepted, branchAFinalVuln.State)
			assert.Len(t, branchAFinalVuln.Events, 3)

			assert.Equal(t, "branch-b", branchBVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateAccepted, branchBVuln.State)
			assert.Len(t, branchBVuln.Events, 3)

			branchBEvents := branchBVuln.Events

			var copiedDetectedEvent models.VulnEvent
			var copiedAcceptedEvent models.VulnEvent
			var copiedCommentEvent models.VulnEvent

			for _, event := range branchBEvents {
				switch event.Type {
				case dtos.EventTypeDetected:
					copiedDetectedEvent = event
				case dtos.EventTypeAccepted:
					copiedAcceptedEvent = event
				case dtos.EventTypeComment:
					copiedCommentEvent = event
				}
			}

			assert.NotEmpty(t, copiedDetectedEvent)
			assert.Equal(t, dtos.EventTypeDetected, copiedDetectedEvent.Type)
			assert.Equal(t, branchBVuln.CalculateHash(), *copiedDetectedEvent.DependencyVulnID)

			assert.NotEmpty(t, copiedAcceptedEvent)
			assert.Equal(t, dtos.EventTypeAccepted, copiedAcceptedEvent.Type)
			assert.Equal(t, "test-user", copiedAcceptedEvent.UserID)
			assert.Equal(t, "Accepting this vulnerability for testing lifecycle management", *copiedAcceptedEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), *copiedAcceptedEvent.DependencyVulnID)

			assert.NotEmpty(t, copiedCommentEvent)
			assert.Equal(t, dtos.EventTypeComment, copiedCommentEvent.Type)
			assert.Equal(t, "test-user", copiedCommentEvent.UserID)
			assert.Equal(t, "This is a test comment for lifecycle verification", *copiedCommentEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), *copiedCommentEvent.DependencyVulnID)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-c")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 3)

			var branchCVuln models.DependencyVuln
			for _, vuln := range vulns {
				if vuln.AssetVersionName == "branch-c" {
					branchCVuln = vuln
				}
			}

			assert.Equal(t, "branch-c", branchCVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateAccepted, branchCVuln.State)
			assert.Len(t, branchCVuln.Events, 3)
		})

		t.Run("should handle false positive events in lifecycle management", func(t *testing.T) {

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, _ := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			for _, vuln := range vulns {
				f.DB.Exec("DELETE FROM artifact_dependency_vulns WHERE dependency_vuln_id = ?", vuln.ID)
				f.DB.Delete(&vuln)
			}

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact-fp")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-d")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchDVuln := vulns[0]

			fpEvent := models.NewFalsePositiveEvent(branchDVuln.ID, branchDVuln.GetType(), "test-user", "This is a false positive", dtos.ComponentNotPresent, "lifecycle-artifact-fp", false)
			err = dependencyVulnRepository.ApplyAndSave(context.Background(), nil, &branchDVuln, &fpEvent)
			assert.Nil(t, err)

			recorder = httptest.NewRecorder()
			sbomFile = sbomWithVulnerability()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "lifecycle-artifact-fp")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-e")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)

			var branchEVuln models.DependencyVuln
			for _, vuln := range vulns {
				if vuln.AssetVersionName == "branch-e" {
					branchEVuln = vuln
				}
			}

			assert.Equal(t, dtos.VulnStateFalsePositive, branchEVuln.State)
			assert.Len(t, branchEVuln.Events, 2)

			var copiedFPEvent models.VulnEvent
			for _, event := range branchEVuln.Events {
				if event.Type == dtos.EventTypeFalsePositive {
					copiedFPEvent = event
					break
				}
			}

			assert.NotEmpty(t, copiedFPEvent)
			assert.Equal(t, "This is a false positive", *copiedFPEvent.Justification)
		})
	})
}

func TestFirstPartyVulnerabilityLifecycleManagement(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController
		firstPartyVulnRepository := f.App.FirstPartyVulnRepository

		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should copy all events when first party vulnerability is found on different branches", func(t *testing.T) {

			vulns, _ := firstPartyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			for _, vuln := range vulns {
				f.DB.Delete(&vuln)
			}

			recorder := httptest.NewRecorder()
			sarifFile := sarifWithFirstPartyVuln()
			req := httptest.NewRequest("POST", "/vulndb/scan/sarif", sarifFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Scanner", "first-party-scanner")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-a")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.FirstPartyVulnScan(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = firstPartyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepted for lifecycle testing", false)
			err = firstPartyVulnRepository.ApplyAndSave(context.Background(), nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Test comment for lifecycle verification", false)
			err = firstPartyVulnRepository.ApplyAndSave(context.Background(), nil, &branchAVuln, &commentEvent)
			assert.Nil(t, err)

			vulns, err = firstPartyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			branchAVuln = vulns[0]
			assert.Equal(t, dtos.VulnStateAccepted, branchAVuln.State)
			assert.Len(t, branchAVuln.Events, 3)

			recorder = httptest.NewRecorder()
			sarifFile = sarifWithFirstPartyVuln()
			req = httptest.NewRequest("POST", "/vulndb/scan/sarif", sarifFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Scanner", "first-party-scanner")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "branch-b")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.FirstPartyVulnScan(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = firstPartyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)

			var branchBVuln models.FirstPartyVuln
			for _, vuln := range vulns {
				if vuln.AssetVersionName == "branch-b" {
					branchBVuln = vuln
				}
			}

			assert.NotEmpty(t, branchBVuln.ID)
			assert.Equal(t, "branch-b", branchBVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateAccepted, branchBVuln.State)
			assert.Len(t, branchBVuln.Events, 3)

			var copiedAcceptedEvent, copiedCommentEvent models.VulnEvent
			for _, event := range branchBVuln.Events {
				switch event.Type {
				case dtos.EventTypeAccepted:
					copiedAcceptedEvent = event
				case dtos.EventTypeComment:
					copiedCommentEvent = event
				}
			}

			assert.NotEmpty(t, copiedAcceptedEvent.ID)
			assert.Equal(t, dtos.EventTypeAccepted, copiedAcceptedEvent.Type)
			assert.Equal(t, "test-user", copiedAcceptedEvent.UserID)
			assert.Equal(t, "Accepted for lifecycle testing", *copiedAcceptedEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), *copiedAcceptedEvent.FirstPartyVulnID)

			assert.NotEmpty(t, copiedCommentEvent.ID)
			assert.Equal(t, dtos.EventTypeComment, copiedCommentEvent.Type)
			assert.Equal(t, "test-user", copiedCommentEvent.UserID)
			assert.Equal(t, "Test comment for lifecycle verification", *copiedCommentEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), *copiedCommentEvent.FirstPartyVulnID)
		})
	})
}

func TestTicketHandling(t *testing.T) {
	testClientFactory, gitlabClientFacade := NewTestClientFactory(t)
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.GitlabClientFactory {
				return testClientFactory
			}),
		},
	}, func(f *TestFixture) {
		controller := f.App.ScanController
		// scan the vulnerable sbom
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		gitlabIntegration := models.GitLabIntegration{
			AccessToken: "access-token",
			GitLabURL:   "https://gitlab.com",
			OrgID:       org.ID,
		}
		err := f.DB.Create(&gitlabIntegration).Error
		assert.Nil(t, err)

		t.Run("should open tickets for vulnerabilities if the risk threshold is exceeded", func(t *testing.T) {

			asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
			asset.RepositoryID = utils.Ptr(fmt.Sprintf("gitlab:%s:123", gitlabIntegration.ID))
			err = f.DB.Save(&asset).Error
			assert.Nil(t, err)

			// scan the sbom with the vulnerability again
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-4")

			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{
				IID: 456,
			}, nil, nil).Once()
			gitlabClientFacade.On("CreateIssueComment", mock.Anything, 123, 456, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
			}).Return(nil, nil, nil).Once()

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
		})

		t.Run("should close existing tickets for vulnerabilities if the vulnerability is fixed", func(t *testing.T) {

			err := f.DB.Clauses(clause.OnConflict{
				UpdateAll: true,
			}).Create(&models.DependencyVuln{
				CVEID:             "CVE-2025-46569",
				ComponentPurl:     "pkg:golang/github.com/open-policy-agent/opa@v0.68.0",
				VulnerabilityPath: []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"},
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					State:            dtos.VulnStateOpen,
					AssetID:          asset.ID,
					// use numeric project id to mimic real stored value format gitlab:<projectID>/<issueIID>
					TicketID: utils.Ptr("gitlab:123/789"),
				},
				Artifacts: []models.Artifact{
					{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
				},
			}).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithoutVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-4")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			gitlabClientFacade.On("EditIssue", mock.Anything, 123, 789, mock.Anything).Return(nil, nil, nil)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
		})

		t.Run("should NOT close existing tickets for vulnerabilities if the vulnerability is still found by a different scanner", func(t *testing.T) {
			// since we mocked CreateIssue, which is responsible of updating the ticket id on a dependency vulnerability, we need to update the dependencyVulnerability manually
			err := f.DB.Clauses(clause.OnConflict{
				UpdateAll: true,
			}).Create(&models.DependencyVuln{
				CVEID:             "CVE-2025-46569",
				ComponentPurl:     "pkg:golang/github.com/open-policy-agent/opa@v0.68.0",
				VulnerabilityPath: []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"},
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					State:            dtos.VulnStateOpen,
					AssetID:          asset.ID,
					TicketID:         utils.Ptr("gitlab:123/789"),
				},
				Artifacts: []models.Artifact{
					{ArtifactName: "some-other-artifact", AssetVersionName: "main", AssetID: asset.ID},
					{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
				},
			}).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithoutVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-4")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
		})

		t.Run("should not create a ticket, if the vulnerability is in an accepted state", func(t *testing.T) {
			// update the cve to exceed this threshold
			cve := models.CVE{
				CVE:  "CVE-2025-46569",
				CVSS: 8.0,
			}
			cve.ID = cve.CalculateHash()
			err = f.DB.Save(&cve).Error
			assert.Nil(t, err)
			if err := f.DB.Exec("DELETE FROM artifact_dependency_vulns adv USING dependency_vulns dv WHERE adv.dependency_vuln_id = dv.id AND dv.cve_id = ?;", "CVE-2025-46569").Error; err != nil {
				panic(err)
			}
			if err := f.DB.Delete(&models.DependencyVuln{}, "cve_id = ?", "CVE-2025-46569").Error; err != nil {
				panic(err)
			}
			// create a vulnerability with an accepted state
			vuln := models.DependencyVuln{
				CVEID:             "CVE-2025-46569",
				ComponentPurl:     "pkg:golang/github.com/open-policy-agent/opa@v0.68.0",
				VulnerabilityPath: []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"},
				Vulnerability: models.Vulnerability{
					State:            dtos.VulnStateAccepted,
					AssetVersionName: "main",
					AssetID:          asset.ID,
				},
				Artifacts: []models.Artifact{
					{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
				},
			}
			err = f.DB.Clauses(clause.OnConflict{
				UpdateAll: true,
			}).Create(&vuln).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-4")
			req.Header.Set("X-Asset-Default-Branch", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
			assert.Equal(t, 0, response.AmountClosed)  // no vulnerabilities closed
			assert.Len(t, response.DependencyVulns, 1) // we expect the accepted vulnerability to be returned
		})
		t.Run("should add the correct path to the component inside the ticket, even if the vulnerability is found by two scanners", func(t *testing.T) {
			// create a vulnerability with an accepted state
			vuln := models.DependencyVuln{
				CVEID:         "CVE-2025-46569",
				ComponentPurl: "pkg:golang/github.com/open-policy-agent/opa@v0.68.0",
				Vulnerability: models.Vulnerability{
					State:            dtos.VulnStateOpen,
					AssetVersionName: "main",
					AssetID:          asset.ID,
					TicketID:         nil,
				},
				VulnerabilityPath: []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"},
				Artifacts: []models.Artifact{
					{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
				},
			}
			err = f.DB.Clauses(clause.OnConflict{
				UpdateAll: true,
			}).Create(&vuln).Error

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-component")
			req.Header.Set("X-Asset-Default-Branch", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			gitlabClientFacade.Calls = nil // reset the calls to the mock
			gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{
				IID: 789,
			}, nil, nil).Once()
			gitlabClientFacade.On("CreateIssueComment", mock.Anything, 123, 789, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
			}).Return(nil, nil, nil).Once()

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			createIssueOptions := gitlabClientFacade.Calls[0].Arguments[2].(*gitlab.CreateIssueOptions)

			assert.Equal(t, "CVE-2025-46569 found in golang/github.com/open-policy-agent/opa@v0.68.0", *createIssueOptions.Title)

			desc := *createIssueOptions.Description
			assert.Contains(t, desc, "CVE-2025-46569")
			assert.Contains(t, desc, "open-policy-agent/opa@v0.68.0")
			assert.Contains(t, desc, "artifact-4")
			assert.Contains(t, desc, "artifact-component")
			assert.Contains(t, desc, "### Recommended fix")
			assert.Contains(t, desc, vuln.ID.String())
		})
	})
}

func createCVE2025_46569(db shared.DB) {
	cve := models.CVE{
		CVE: "CVE-2025-46569",
	}

	err := db.Create(&cve).Error
	if err != nil {
		panic(err)
	}

	affectedComponent := models.AffectedComponent{
		PurlWithoutVersion: "pkg:golang/github.com/open-policy-agent/opa",
		SemverFixed:        utils.Ptr("1.4.0"),
	}

	err = db.Create(&affectedComponent).Error
	if err != nil {
		panic(err)
	}

	// create the relationship between the CVE and the affected component
	err = db.Model(&cve).Association("AffectedComponents").Append(&affectedComponent)
	if err != nil {
		panic(err)
	}
}

func emptySbom() io.Reader {
	content := getEmptySBOMContent()
	return bytes.NewReader(content)
}

func sbomWithVulnerability() io.Reader {
	content := getSBOMWithVulnerabilityContent()
	return bytes.NewReader(content)
}

func sbomWithoutVulnerability() io.Reader {
	content := getSBOMWithoutVulnerabilityContent()
	return bytes.NewReader(content)
}

func getEmptySBOMContent() []byte {
	file, err := os.Open("./testdata/empty-sbom.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return content
}

func getSBOMWithVulnerabilityContent() []byte {
	file, err := os.Open("./testdata/sbom-with-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return content
}

func getSBOMWithoutVulnerabilityContent() []byte {
	file, err := os.Open("./testdata/sbom-without-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return content
}

func sarifWithFirstPartyVuln() *strings.Reader {
	sarifContent := `{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "test-scanner",
						"version": "1.0.0",
						"rules": [
							{
								"id": "test-rule-fp",
								"name": "Test Security Rule",
								"shortDescription": {
									"text": "A test security vulnerability"
								},
								"fullDescription": {
									"text": "This is a test security vulnerability for lifecycle testing"
								},
								"help": {
									"text": "Fix this vulnerability by updating the code"
								}
							}
						]
					}
				},
				"results": [
					{
						"ruleId": "test-rule-fp",
						"message": {
							"text": "Test security issue found"
						},
						"locations": [
							{
								"physicalLocation": {
									"artifactLocation": {
										"uri": "src/test.go"
									},
									"region": {
										"startLine": 10,
										"endLine": 10,
										"startColumn": 5,
										"endColumn": 15,
										"snippet": {
											"text": "vulnerable code"
										}
									}
								}
							}
						]
					}
				]
			}
		]
	}`
	return strings.NewReader(sarifContent)
}

func TestIdempotency(t *testing.T) {
	// 1. scan a sbom
	// 2. Download the sbom from devguard
	// 3. Scan that sbom
	// 4. Download it
	// 5. compare 2 and 4
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController
		app := echo.New()
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		artifactController := f.App.ArtifactController

		setupContext := func(ctx shared.Context) {
			authSession := mocks.AuthSession{}

			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, &authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		t.Run("scanning the same sbom multiple times should yield the same result", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "idempotency-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// now download the sbom
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", fmt.Sprintf("/assets/%s/asset-versions/%s/sbom/normalized", asset.ID, "idempotency-artifact"), nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "idempotency-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)
			firstDownload := recorder.Body.String()

			// scan the downloaded sbom again
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader([]byte(firstDownload)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "idempotency-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// download again
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", fmt.Sprintf("/assets/%s/asset-versions/%s/sbom/normalized", asset.ID, "idempotency-artifact"), nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "idempotency-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})
			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)
			secondDownload := recorder.Body.String()
			// parse both jsons and compare them by properties
			// there are arrays in the sbom, so direct string comparison might fail due to different ordering
			var firstSBOM, secondSBOM cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(firstDownload), cyclonedx.BOMFileFormatJSON).Decode(&firstSBOM)
			assert.Nil(t, err)
			err = cyclonedx.NewBOMDecoder(strings.NewReader(secondDownload), cyclonedx.BOMFileFormatJSON).Decode(&secondSBOM)
			assert.Nil(t, err)

			// compare the root component
			assert.Equal(t, firstSBOM.Metadata.Component.BOMRef, firstSBOM.Metadata.Component.BOMRef)
			// check components are the same
			assert.ElementsMatch(t, *firstSBOM.Components, *secondSBOM.Components)
			// build a dependency map
			for _, firstDep := range *firstSBOM.Dependencies {
				for _, secondDep := range *secondSBOM.Dependencies {
					if secondDep.Ref == firstDep.Ref {
						if firstDep.Dependencies == nil && secondDep.Dependencies == nil {
							continue
						}
						assert.ElementsMatch(t, *firstDep.Dependencies, *secondDep.Dependencies)
					}
				}
			}
		})
	})
}

func TestOnlyFixingVulnerabilitiesWithASinglePath(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		// load small-sbom.json
		smallSbom, err := os.Open("testdata/small-sbom.json")
		assert.Nil(t, err)

		smallVex, err := os.Open("testdata/small-vex-false-positive.json")
		assert.Nil(t, err)

		newCVE := models.CVE{
			CVE:         "CVE-2020-25649",
			Description: "Test",
			CVSS:        6.00,
		}
		if err = f.DB.Create(&newCVE).Error; err != nil {
			t.Fatalf("could not create cve 2: %v", err)
		}

		// Create AffectedComponent to link the CVE to the package
		// This ensures the SBOM scan will find this vulnerability for the package
		affectedComp := models.AffectedComponent{
			PurlWithoutVersion: "pkg:golang/github.com/jinzhu/inflection",
			Ecosystem:          "golang",
			Version:            utils.Ptr("1.0.0"),
			CVE:                []models.CVE{newCVE},
		}
		if err = f.DB.Create(&affectedComp).Error; err != nil {
			t.Fatalf("could not create affected component: %v", err)
		}

		controller := f.App.ScanController

		app := echo.New()

		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", smallVex)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "idempotency-artifact")
		req.Header.Set("X-Asset-Default-Branch", "main")
		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)

		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := mocks.AuthSession{}

			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, &authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		setupContext(ctx)

		assert.Nil(t, controller.UploadVEX(ctx))

		// now scan the sbom - it contains the package that the vex is talking about
		// the SBOM scan will create the dependency vuln for CVE-2020-25649
		// and the VEX rule will apply to it, putting it in false positive state
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", smallSbom)
		recorder = httptest.NewRecorder()
		ctx = app.NewContext(req, recorder)
		setupContext(ctx)
		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		// make a query to the vulnerability and expect it in falsePositive state
		result := models.DependencyVuln{}
		assert.Nil(t, f.DB.Model(&models.DependencyVuln{}).Where("asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).First(&result).Error)

		assert.Equal(t, dtos.VulnStateFalsePositive, result.State)
	})
}

func TestScanWithMultiplePaths(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController

		// scan the sbom with multiple paths to the same vulnerable dependency
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should detect vulnerability with multiple dependency paths", func(t *testing.T) {
			sbomFile, err := os.Open("testdata/sbom-with-multiple-paths.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "multi-path-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "multi-path-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)

			assert.Equal(t, 200, recorder.Code)
			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)

			assert.Equal(t, 2, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 2)
		})
	})
}

func TestPathPatternVEXRules(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController
		dependencyVulnRepository := f.App.DependencyVulnRepository

		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		t.Run("should apply VEX rule to all vulns with matching path suffix", func(t *testing.T) {
			// First, scan the SBOM with multiple paths to create vulnerabilities
			sbomFile, err := os.Open("testdata/sbom-with-multiple-paths.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "path-pattern-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "path-pattern-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var response dtos.ScanResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &response)
			assert.Nil(t, err)
			assert.Equal(t, 2, response.AmountOpened, "should have created 2 vulnerabilities with different paths")

			// Get the vulnerabilities from DB
			vulns, err := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)

			// Both should be in open state
			for _, v := range vulns {
				assert.Equal(t, dtos.VulnStateOpen, v.State)
			}

			// Create a VEX rule via the new dedicated endpoint
			pathPattern := []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"}
			ruleBody := fmt.Sprintf(`{"cveId":"CVE-2025-46569","justification":"Not exploitable in our context","mechanicalJustification":"componentNotPresent","pathPattern":["%s"]}`, pathPattern[0])
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/false-positive-rules", strings.NewReader(ruleBody))
			req.Header.Set("Content-Type", "application/json")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			vexRuleController := f.App.VEXRuleController
			err = vexRuleController.Create(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 201, recorder.Code)

			// Re-fetch the vulnerabilities to check their state after VEX rule is applied
			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)

			falsePositiveCount := 0
			for _, v := range vulns {
				if v.State == dtos.VulnStateFalsePositive {
					falsePositiveCount++
				}
			}
			assert.Equal(t, 2, falsePositiveCount, "both vulnerabilities should be marked as false positive by VEX rule")
		})
	})
}

func TestPathPatternRuleAppliedToNewVulns(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {

		controller := f.App.ScanController
		dependencyVulnRepository := f.App.DependencyVulnRepository
		vexRuleController := f.App.VEXRuleController

		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		t.Run("should apply existing VEX rule to newly detected vulns with matching path", func(t *testing.T) {
			// First, scan to create the initial vulnerability
			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "rule-test-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "rule-test-origin")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Get the vulnerability
			vulns, err := dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)
			assert.GreaterOrEqual(t, len(vulns), 1)

			// Find the vuln we just created
			var initialVuln *models.DependencyVuln
			for i := range vulns {
				if vulns[i].AssetVersionName == "main" && vulns[i].CVEID == "CVE-2025-46569" {
					initialVuln = &vulns[i]
					break
				}
			}
			assert.NotNil(t, initialVuln)

			// Create a VEX rule via the new dedicated endpoint
			pathPattern := []string{"pkg:golang/github.com/open-policy-agent/opa@v0.68.0"}
			ruleBody := fmt.Sprintf(`{"cveId":"CVE-2025-46569","justification":"OPA is not exploitable in our context","mechanicalJustification":"componentNotPresent","pathPattern":["%s"]}`, pathPattern[0])
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/false-positive-rules", strings.NewReader(ruleBody))
			req.Header.Set("Content-Type", "application/json")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = vexRuleController.Create(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 201, recorder.Code)

			// Now scan a different SBOM that creates a new vuln with the same path suffix
			// Using sbom-with-multiple-paths which has OPA at the end of multiple paths
			sbomFile2, err := os.Open("testdata/sbom-with-multiple-paths.json")
			assert.Nil(t, err)
			defer sbomFile2.Close()

			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile2)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "rule-test-artifact-2")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "rule-test-origin-2")
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Get all vulns again
			vulns, err = dependencyVulnRepository.GetByAssetID(context.Background(), nil, asset.ID)
			assert.Nil(t, err)

			// Find the new vulns (those with path-a or path-b in their path)
			newVulnsFalsePositiveCount := 0
			for _, v := range vulns {
				// Check if this vuln has the matching path suffix
				if len(v.VulnerabilityPath) > 0 {
					lastElement := v.VulnerabilityPath[len(v.VulnerabilityPath)-1]
					if lastElement == "pkg:golang/github.com/open-policy-agent/opa@v0.68.0" {
						if v.State == dtos.VulnStateFalsePositive {
							newVulnsFalsePositiveCount++
						}
					}
				}
			}

			// All vulns with matching path suffix should be false positive
			assert.GreaterOrEqual(t, newVulnsFalsePositiveCount, 2, "newly detected vulns with matching path should be marked as false positive by the existing rule")
		})
	})
}

func TestKeepOriginalRootComponentHeaderTrue(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController
		artifactController := f.App.ArtifactController

		app := echo.New()
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// The original root component bom-ref from small-sbom.json
		originalRootRef := "pkg:devguard/neu@main"

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user").Maybe()
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		// Helper function to check if the original root component exists in the components array
		hasOriginalRootInComponents := func(bom *cyclonedx.BOM) bool {
			if bom.Components == nil {
				return false
			}
			for _, comp := range *bom.Components {
				if comp.PackageURL == originalRootRef {
					return true
				}
			}
			return false
		}

		t.Run("should override to true when header is 1", func(t *testing.T) {
			// Set asset to NOT keep original root component
			asset.KeepOriginalSbomRootComponent = false
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "header-1-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Keep-Original-SBOM-Root-Component", "1") // Override to true
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Download the SBOM and verify the original root component is preserved
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", "/sbom/json", nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "header-1-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(recorder.Body.String()), cyclonedx.BOMFileFormatJSON).Decode(&bom)
			assert.Nil(t, err)

			// With header=1, the original root component from the SBOM should be preserved
			// in the components array (even though asset default is false)
			assert.NotNil(t, bom.Metadata)
			assert.NotNil(t, bom.Metadata.Component)
			assert.True(t, hasOriginalRootInComponents(&bom), "original root component should be in components array when header=1")
		})

		t.Run("should use asset default true when no header provided", func(t *testing.T) {
			// Set asset to keep original root component
			asset.KeepOriginalSbomRootComponent = true
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "asset-default-true-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			// No X-Keep-Original-SBOM-Root-Component header - should use asset default (true)
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Download the SBOM and verify original root component is preserved
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", "/sbom/json", nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "asset-default-true-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(recorder.Body.String()), cyclonedx.BOMFileFormatJSON).Decode(&bom)
			assert.Nil(t, err)

			// With asset.KeepOriginalSbomRootComponent=true and no header,
			// the original root component should be in the components array
			assert.NotNil(t, bom.Metadata)
			assert.NotNil(t, bom.Metadata.Component)
			assert.True(t, hasOriginalRootInComponents(&bom), "original root component should be in components array when asset default is true")
		})
	})
}

func TestKeepOriginalRootComponentHeaderFalse(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController
		artifactController := f.App.ArtifactController

		app := echo.New()
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// The original root component bom-ref from small-sbom.json
		originalRootRef := "pkg:devguard/neu@main"

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user").Maybe()
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
			shared.SetAssetVersion(ctx, assetVersion)
		}

		// Helper function to check if the original root component exists in the components array
		hasOriginalRootInComponents := func(bom *cyclonedx.BOM) bool {
			if bom.Components == nil {
				return false
			}
			for _, comp := range *bom.Components {
				if comp.PackageURL == originalRootRef {
					return true
				}
			}
			return false
		}

		t.Run("should use asset default when no header is provided", func(t *testing.T) {
			// Set asset to NOT keep original root component
			asset.KeepOriginalSbomRootComponent = false
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "no-header-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			// No X-Keep-Original-SBOM-Root-Component header
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Download the SBOM and verify root component handling
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", "/sbom/json", nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "no-header-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(recorder.Body.String()), cyclonedx.BOMFileFormatJSON).Decode(&bom)
			assert.Nil(t, err)

			// With KeepOriginalSbomRootComponent=false, the original root component
			// should NOT be present in the components array
			assert.NotNil(t, bom.Metadata)
			assert.NotNil(t, bom.Metadata.Component)
			assert.False(t, hasOriginalRootInComponents(&bom), "original root component should NOT be in components array when keepOriginalSbomRootComponent=false")
		})

		t.Run("should override to false when header is 0", func(t *testing.T) {
			// Set asset to keep original root component
			asset.KeepOriginalSbomRootComponent = true
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "header-0-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Keep-Original-SBOM-Root-Component", "0") // Override to false
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Download the SBOM and verify root component handling
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", "/sbom/json", nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "header-0-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(recorder.Body.String()), cyclonedx.BOMFileFormatJSON).Decode(&bom)
			assert.Nil(t, err)

			// With header=0, the original root component should NOT be in the components array
			// (even though asset default is true)
			assert.NotNil(t, bom.Metadata)
			assert.NotNil(t, bom.Metadata.Component)
			assert.False(t, hasOriginalRootInComponents(&bom), "original root component should NOT be in components array when header=0")
		})

		t.Run("should ignore invalid header values", func(t *testing.T) {
			// Set asset to NOT keep original root component
			asset.KeepOriginalSbomRootComponent = false
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile, err := os.Open("testdata/small-sbom.json")
			assert.Nil(t, err)
			defer sbomFile.Close()

			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "invalid-header-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Keep-Original-SBOM-Root-Component", "invalid") // Invalid value
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Download the SBOM and verify default behavior (asset setting) is used
			recorder = httptest.NewRecorder()
			req = httptest.NewRequest("GET", "/sbom/json", nil)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)
			shared.SetArtifact(ctx, models.Artifact{ArtifactName: "invalid-header-artifact", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

			err = artifactController.SBOMJSON(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(strings.NewReader(recorder.Body.String()), cyclonedx.BOMFileFormatJSON).Decode(&bom)
			assert.Nil(t, err)

			// With invalid header, should fall back to asset default (false)
			// So the original root component should NOT be in components array
			assert.NotNil(t, bom.Metadata)
			assert.NotNil(t, bom.Metadata.Component)
			assert.False(t, hasOriginalRootInComponents(&bom), "original root component should NOT be in components array when header is invalid (falls back to asset default=false)")
		})
	})
}

// TestTrivyDebianSBOMRescan reproduces the FK violation on component_dependencies.
// When a component is missing from the components table (e.g. deleted externally,
// or evicted by a concurrent transaction), a rescan must still succeed by
// re-inserting the missing component before creating the dependency edge.
func TestTrivyDebianSBOMRescan(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController
		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		sbomBytes, err := os.ReadFile("../normalize/testdata/trivy-debian-sbom.json")
		assert.NoError(t, err)

		doScan := func(label string) error {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/scan", bytes.NewReader(sbomBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "trivy-debian-image")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "trivy")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			if err := controller.ScanDependencyVulnFromProject(ctx); err != nil {
				return fmt.Errorf("%s: controller error: %w", label, err)
			}
			if recorder.Code != 200 {
				return fmt.Errorf("%s: expected 200, got %d, body: %s", label, recorder.Code, recorder.Body.String())
			}
			return nil
		}

		// First scan: populates the components table.
		assert.NoError(t, doScan("scan 1"))

		// Delete one of the components with a %2B-encoded PURL from the DB to
		// simulate the state that causes the FK violation on the next scan.
		// The libc6 component has PURL pkg:deb/debian/libc6@2.36-9+deb12u10?...
		// (stored decoded with '+'); removing it means the next scan must
		// re-insert it before creating the edge.
		libc6Purl := "pkg:deb/debian/libc6@2.36-9+deb12u10?arch=amd64&distro=debian-12.11"
		result := f.DB.Exec("DELETE FROM components WHERE id = ?", libc6Purl)
		assert.NoError(t, result.Error)
		assert.Equal(t, int64(1), result.RowsAffected, "libc6 component should have been deleted")

		// Second scan: must succeed even though libc6 is missing from components.
		assert.NoError(t, doScan("scan 2 (after component deleted)"))
	})
}

func TestKeepOriginalRootComponentRejectsSbomWithoutPurl(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.ScanController

		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		t.Run("should return 400 when asset keepOriginalSbomRootComponent is true and SBOM has no root PURL", func(t *testing.T) {
			asset.KeepOriginalSbomRootComponent = true
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := emptySbom() // empty-sbom.json has metadata.component but no PackageURL
			req := httptest.NewRequest("POST", "/scan", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "no-purl-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.NotNil(t, err)

			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok, "error should be an echo.HTTPError")
			assert.Equal(t, 400, he.Code)
		})

		t.Run("should return 400 when header overrides to true and SBOM has no root PURL", func(t *testing.T) {
			asset.KeepOriginalSbomRootComponent = false
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := emptySbom()
			req := httptest.NewRequest("POST", "/scan", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "no-purl-header-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Keep-Original-SBOM-Root-Component", "1")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.NotNil(t, err)

			he, ok := err.(*echo.HTTPError)
			assert.True(t, ok, "error should be an echo.HTTPError")
			assert.Equal(t, 400, he.Code)
		})

		t.Run("should succeed when keepOriginalSbomRootComponent is false and SBOM has no root PURL", func(t *testing.T) {
			asset.KeepOriginalSbomRootComponent = false
			err := f.DB.Save(&asset).Error
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := emptySbom()
			req := httptest.NewRequest("POST", "/scan", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "no-purl-ok-artifact")
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)
		})
	})
}
