package tests

import (
	"bytes"
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
			assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
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
			assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
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
			assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
			assert.Len(t, response.DependencyVulns[0].Artifacts, 1)

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
			assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
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
			assert.Equal(t, 0, response.AmountOpened)
			assert.Equal(t, 0, response.AmountClosed)

			assert.Len(t, response.DependencyVulns, 1)

			if len(response.DependencyVulns) > 0 {
				assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
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
			assert.Equal(t, 1, response.AmountClosed)
			assert.Len(t, response.DependencyVulns, 0)
		})

		t.Run("should respect, if the vulnerability is found AGAIN on a different branch then the default branch", func(t *testing.T) {

			dependencyVulnRepository := f.App.DependencyVulnRepository
			vulns, err := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			acceptedEvent := models.NewAcceptedEvent(vulns[0].ID, vulns[0].GetType(), "abc", "accepting the vulnerability", 0)
			err = dependencyVulnRepository.ApplyAndSave(nil, &vulns[0], &acceptedEvent)
			assert.Nil(t, err)

			recorder := httptest.NewRecorder()
			sbomFile := sbomWithVulnerability()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "artifact-1")
			req.Header.Set("X-Asset-Ref", "some-other-branch")
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)
			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 2)

			for _, vuln := range vulns {
				assert.Equal(t, dtos.VulnStateAccepted, vuln.State)
			}
			var newVuln models.DependencyVuln
			for _, v := range vulns {
				if v.AssetVersionName == "some-other-branch" {
					newVuln = v
				}
			}

			assert.NotEmpty(t, newVuln.Events)
			lastTwoEvents := newVuln.Events[len(newVuln.Events)-2:]

			var accEvent models.VulnEvent
			var detectedOnAnotherBranchEvent models.VulnEvent
			for _, ev := range lastTwoEvents {
				if ev.Type == dtos.EventTypeAccepted {
					accEvent = ev
				} else {
					detectedOnAnotherBranchEvent = ev
				}
			}

			assert.NotEmpty(t, accEvent)
			assert.NotEmpty(t, detectedOnAnotherBranchEvent)
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
			vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			for _, vuln := range vulns {
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing state management", 0)
			err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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
			vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			for _, vuln := range vulns {
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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
			vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			for _, vuln := range vulns {
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing lifecycle management", 0)
			err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "This is a test comment for lifecycle verification", 0)
			err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &commentEvent)
			assert.Nil(t, err)

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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
			assert.Equal(t, branchBVuln.CalculateHash(), copiedDetectedEvent.VulnID)

			assert.NotEmpty(t, copiedAcceptedEvent)
			assert.Equal(t, dtos.EventTypeAccepted, copiedAcceptedEvent.Type)
			assert.Equal(t, "test-user", copiedAcceptedEvent.UserID)
			assert.Equal(t, "Accepting this vulnerability for testing lifecycle management", *copiedAcceptedEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), copiedAcceptedEvent.VulnID)

			assert.NotEmpty(t, copiedCommentEvent)
			assert.Equal(t, dtos.EventTypeComment, copiedCommentEvent.Type)
			assert.Equal(t, "test-user", copiedCommentEvent.UserID)
			assert.Equal(t, "This is a test comment for lifecycle verification", *copiedCommentEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), copiedCommentEvent.VulnID)

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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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
			vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			for _, vuln := range vulns {
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchDVuln := vulns[0]

			fpEvent := models.NewFalsePositiveEvent(branchDVuln.ID, branchDVuln.GetType(), "test-user", "This is a false positive", dtos.ComponentNotPresent, "lifecycle-artifact-fp", 0)
			err = dependencyVulnRepository.ApplyAndSave(nil, &branchDVuln, &fpEvent)
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

			vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, _ := firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, vulns, 1)
			branchAVuln := vulns[0]
			assert.Equal(t, "branch-a", branchAVuln.AssetVersionName)
			assert.Equal(t, dtos.VulnStateOpen, branchAVuln.State)

			acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepted for lifecycle testing", 0)
			err = firstPartyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
			assert.Nil(t, err)

			commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Test comment for lifecycle verification", 0)
			err = firstPartyVulnRepository.ApplyAndSave(nil, &branchAVuln, &commentEvent)
			assert.Nil(t, err)

			vulns, err = firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
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

			vulns, err = firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
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
			assert.Equal(t, branchBVuln.CalculateHash(), copiedAcceptedEvent.VulnID)

			assert.NotEmpty(t, copiedCommentEvent.ID)
			assert.Equal(t, dtos.EventTypeComment, copiedCommentEvent.Type)
			assert.Equal(t, "test-user", copiedCommentEvent.UserID)
			assert.Equal(t, "Test comment for lifecycle verification", *copiedCommentEvent.Justification)
			assert.Equal(t, branchBVuln.CalculateHash(), copiedCommentEvent.VulnID)
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

			cve := models.CVE{
				CVE:  "CVE-2025-46569",
				CVSS: 8.0,
			}
			err = f.DB.Save(&cve).Error
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
				CVEID:         utils.Ptr("CVE-2025-46569"),
				ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
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

			gitlabClientFacade.On("EditIssue", mock.Anything, 123, 789, mock.Anything).Return(nil, nil, nil).Once()

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
		})

		t.Run("should NOT close existing tickets for vulnerabilities if the vulnerability is still found by a different scanner", func(t *testing.T) {
			// since we mocked CreateIssue, which is responsible of updating the ticket id on a dependency vulnerability, we need to update the dependencyVulnerability manually
			err := f.DB.Clauses(clause.OnConflict{
				UpdateAll: true,
			}).Create(&models.DependencyVuln{
				CVEID:         utils.Ptr("CVE-2025-46569"),
				ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
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
			err = f.DB.Save(&cve).Error
			assert.Nil(t, err)

			if err := f.DB.Delete(&models.DependencyVuln{}, "cve_id = ?", "CVE-2025-46569").Error; err != nil {
				panic(err)
			}
			// create a vulnerability with an accepted state
			vuln := models.DependencyVuln{
				CVEID:         utils.Ptr("CVE-2025-46569"),
				ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
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
				CVEID:         utils.Ptr("CVE-2025-46569"),
				ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
				Vulnerability: models.Vulnerability{
					State:            dtos.VulnStateOpen,
					AssetVersionName: "main",
					AssetID:          asset.ID,
					TicketID:         nil,
				},
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
			assert.Contains(t, desc, vuln.ID)
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
		Scheme:             "pkg",
		Type:               "golang",
		Name:               "github.com/open-policy-agent/opa",
		Namespace:          utils.Ptr(""),
		Qualifiers:         utils.Ptr(""),
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

func TestUploadVEX(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()

		scanController := f.App.ScanController
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		asset.ParanoidMode = false
		if err := f.DB.Save(&asset).Error; err != nil {
			t.Fatalf("could not save asset: %v", err)
		}

		setupContext := func(ctx *shared.Context) {
			shared.SetAsset(*ctx, asset)
			shared.SetProject(*ctx, project)
			shared.SetOrg(*ctx, org)
			shared.SetAssetVersion(*ctx, assetVersion)

			// attach an authenticated session for UploadVEX handler
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetSession(*ctx, authSession)
		}

		// create fresh dependency vulns (two entries for same new CVE) so they are not pre-fixed
		var err error
		newCVE := models.CVE{
			CVE:         "CVE-2025-00001",
			Description: "Test upload vex",
			CVSS:        5.00,
		}
		if err = f.DB.Create(&newCVE).Error; err != nil {
			t.Fatalf("could not create cve: %v", err)
		}

		newCVE2 := models.CVE{
			CVE:         "CVE-2025-00002",
			Description: "Test upload vex 2",
			CVSS:        6.00,
		}
		if err = f.DB.Create(&newCVE2).Error; err != nil {
			t.Fatalf("could not create cve 2: %v", err)
		}

		dv1 := models.DependencyVuln{
			Vulnerability:     models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open"},
			ComponentPurl:     utils.Ptr("pkg:npm/example1@1.0.0"),
			CVE:               &newCVE,
			CVEID:             &newCVE.CVE,
			RawRiskAssessment: utils.Ptr(1.23),
			ComponentDepth:    utils.Ptr(1),
		}
		if err = f.DB.Create(&dv1).Error; err != nil {
			t.Fatalf("could not create dependency vuln 1: %v", err)
		}

		dv2 := models.DependencyVuln{
			Vulnerability:     models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open"},
			ComponentPurl:     utils.Ptr("pkg:npm/example2@2.0.0"),
			CVE:               &newCVE2,
			CVEID:             &newCVE2.CVE,
			RawRiskAssessment: utils.Ptr(2.34),
			ComponentDepth:    utils.Ptr(2),
		}
		if err = f.DB.Create(&dv2).Error; err != nil {
			t.Fatalf("could not create dependency vuln 2: %v", err)
		}

		//create a component and save it to the db
		component := models.Component{
			ID:      "pkg:npm/example1@1.0.0",
			License: utils.Ptr("MIT"),
		}

		if err = f.DB.Create(&component).Error; err != nil {
			t.Fatalf("could not create component: %v", err)
		}

		// build a CycloneDX BOM with a single vulnerability (CVE) marked as resolved
		vuln := cyclonedx.Vulnerability{
			ID: "CVE-2025-00001",
			Source: &cyclonedx.Source{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/vuln/detail/CVE-2025-00001",
			},
			Analysis: &cyclonedx.VulnerabilityAnalysis{
				State:  cyclonedx.IASFalsePositive,
				Detail: "We are never using this dependency, so marking as false positive",
			},
			Affects: &[]cyclonedx.Affects{
				{
					Ref: "pkg:npm/example1@1.0.0",
				},
			},
		}
		bom := cyclonedx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cyclonedx.SpecVersion1_6,
			Version:     1,
			Metadata: &cyclonedx.Metadata{
				Component: &cyclonedx.Component{
					BOMRef: "root",
				},
			},
			Vulnerabilities: &[]cyclonedx.Vulnerability{vuln},
		}

		// encode BOM into multipart form
		var body bytes.Buffer

		if err != nil {
			t.Fatalf("could not create form file: %v", err)
		}
		if err := cyclonedx.NewBOMEncoder(&body, cyclonedx.BOMFileFormatJSON).Encode(&bom); err != nil {
			t.Fatalf("could not encode bom: %v", err)
		}

		// perform POST request to UploadVEX
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vex/", &body)
		req.Header.Set("Content-Type", "application/json")
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)

		err = scanController.UploadVEX(ctx)
		assert.Nil(t, err)

		resp := recorder.Result()
		respBody, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)

		var result map[string]int
		err = json.Unmarshal(respBody, &result)
		assert.Nil(t, err)

		// verify DB: both dependency vulns should now be fixed
		var dv []models.DependencyVuln
		if err := f.DB.Where("asset_version_name = ? AND asset_id = ?", assetVersion.Name, asset.ID).Preload("Events", func(db shared.DB) shared.DB {
			return db.Order("created_at ASC")
		}).Find(&dv).Error; err != nil {
			t.Fatalf("could not query dependency vulns: %v", err)
		}
		assert.GreaterOrEqual(t, len(dv), 2)

		for _, d := range dv {
			switch *d.CVEID {
			case "CVE-2025-00001":
				// i think its a race condition and the ordering of events is non deterministic
				assert.Equal(t, dtos.VulnStateFalsePositive, d.State)
				assert.Equal(t, dtos.EventTypeFalsePositive, d.Events[1].Type)
				assert.Equal(t, "We are never using this dependency, so marking as false positive", *d.Events[1].Justification)
			case "CVE-2025-00002":
				assert.Equal(t, dtos.VulnStateOpen, d.State) // was not part of the uploaded vex.
			}
		}
	})
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
		assetVersionController := f.App.AssetVersionController

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

			err = assetVersionController.SBOMJSON(ctx)
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
			err = assetVersionController.SBOMJSON(ctx)
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

		// now scan the sbom - it does not contain the cve the vex is talking about
		// nevertheless, we expect this vulnerability to stay in false positive state and wont be fixed
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
