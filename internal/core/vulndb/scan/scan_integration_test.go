package scan_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"gorm.io/gorm/clause"
)

// Helper to extract artifact names from []models.Artifact
func getArtifactNames(artifacts []models.Artifact) []string {
	names := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		names = append(names, a.ArtifactName)
	}
	return names
}

func TestScanning(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, _ := initHTTPController(t, db, true)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should find a vulnerability in the SBOM", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()

		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-1")
		req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
		req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse

		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 1, response.AmountOpened)
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
	})

	t.Run("should add the artifact, if the vulnerability is found with another artifact", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different artifact, the artifacts get updated
		recorder := httptest.NewRecorder()
		// reopen file - get a fresh file pointer
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-2")
		req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
		req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, 0, response.AmountOpened) // already detected with other artifact
		assert.Equal(t, 0, response.AmountClosed)

		assert.Len(t, response.DependencyVulns, 1)

		if len(response.DependencyVulns) > 0 {
			assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
			// the artifacts should be updated
			assert.ElementsMatch(t, []string{"artifact-1", "artifact-2"}, getArtifactNames(response.DependencyVulns[0].Artifacts))
		}
	})

	t.Run("should return vulnerabilities, which are found by the current artifact", func(t *testing.T) {
		// scan the sbom without the vulnerability
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-3")
		req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
		req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened) // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})

	t.Run("should return amount of closed 1, if the vulnerability is not detected by ANY artifact anymore", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different artifact, the artifacts get updated
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-1")
		req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
		req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)  // the vulnerability was not closed - still found by artifact 2
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned

		sbomFile2 := sbomWithoutVulnerability()
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile2)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-2")
		req.Header.Set("X-Asset-Default-Branch", "main") // set the default branch header
		req.Header.Set("X-Asset-Ref", "main")            // set the asset ref header
		recorder = httptest.NewRecorder()
		ctx = app.NewContext(req, recorder)
		setupContext(ctx)
		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 1, response.AmountClosed)  // the vulnerability is finally closed
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})

	t.Run("should respect, if the vulnerability is found AGAIN on a different branch then the default branch", func(t *testing.T) {

		dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
		vulns, err := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		// should be only a single vulnerability
		assert.Nil(t, err)
		assert.Len(t, vulns, 1)
		// create an accepted event inside the database
		acceptedEvent := models.NewAcceptedEvent(vulns[0].ID, vulns[0].GetType(), "abc", "accepting the vulnerability")
		err = dependencyVulnRepository.ApplyAndSave(nil, &vulns[0], &acceptedEvent)
		assert.Nil(t, err)
		// now scan a different branch with the same vulnerability
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-1")
		req.Header.Set("X-Asset-Ref", "some-other-branch")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx) //setup context
		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)

		// query the new vulnerability
		vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		// should be two now
		assert.Nil(t, err)
		assert.Len(t, vulns, 2)

		// both should be accepted
		for _, vuln := range vulns {
			assert.Equal(t, models.VulnStateAccepted, vuln.State)
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
			if ev.Type == models.EventTypeAccepted {
				accEvent = ev
			} else {
				detectedOnAnotherBranchEvent = ev
			}
		}

		assert.NotEmpty(t, accEvent)
		assert.NotEmpty(t, detectedOnAnotherBranchEvent)
		assert.Equal(t, models.EventTypeAccepted, accEvent.Type)
		assert.Equal(t, "accepting the vulnerability", *accEvent.Justification)
		assert.Equal(t, "main", *accEvent.OriginalAssetVersionName)
	})
}

func TestVulnerabilityStateOnMultipleArtifacts(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, _ := initHTTPController(t, db, true)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should copy the events one time from a different branch even if the vulnerability is exiting on multiple artifacts", func(t *testing.T) {

		dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
		vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		for _, vuln := range vulns {
			db.Delete(&vuln)
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
		assert.Equal(t, models.VulnStateOpen, branchAVuln.State)

		acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing state management")
		err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
		assert.Nil(t, err)

		vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		assert.Nil(t, err)
		branchAVuln = vulns[0]
		assert.Equal(t, models.VulnStateAccepted, branchAVuln.State)

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
		assert.Equal(t, models.VulnStateAccepted, branchAVuln.State)
		assert.Len(t, branchAVuln.Events, 2)

	})

}

func TestVulnerabilityLifecycleManagementOnMultipleArtifacts(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, _ := initHTTPController(t, db, true)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should copy the events one time from a different branch even if the vulnerability is exiting on multiple artifacts", func(t *testing.T) {

		dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
		vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		for _, vuln := range vulns {
			db.Delete(&vuln)
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
		assert.Equal(t, models.VulnStateOpen, branchAVuln.State)

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
		assert.Equal(t, models.VulnStateOpen, branchAVuln.State)
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
		assert.Equal(t, models.VulnStateOpen, branchAFinalVuln.State)
		assert.Len(t, branchAFinalVuln.Events, 1)
		assert.Equal(t, "branch-b", branchBVuln.AssetVersionName)
		assert.Equal(t, models.VulnStateOpen, branchBVuln.State)
		assert.Len(t, branchBVuln.Events, 1) // only one event should be copied
	})

}

func TestVulnerabilityLifecycleManagement(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, _ := initHTTPController(t, db, true)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should copy all events when vulnerability is found on different branches - complete lifecycle test", func(t *testing.T) {

		dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
		vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		for _, vuln := range vulns {
			db.Delete(&vuln)
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
		assert.Equal(t, models.VulnStateOpen, branchAVuln.State)

		acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepting this vulnerability for testing lifecycle management")
		err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
		assert.Nil(t, err)

		commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "This is a test comment for lifecycle verification")
		err = dependencyVulnRepository.ApplyAndSave(nil, &branchAVuln, &commentEvent)
		assert.Nil(t, err)

		vulns, err = dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		assert.Nil(t, err)
		assert.Len(t, vulns, 1)
		branchAVuln = vulns[0]
		assert.Equal(t, models.VulnStateAccepted, branchAVuln.State)
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
		assert.Equal(t, models.VulnStateAccepted, branchAFinalVuln.State)
		assert.Len(t, branchAFinalVuln.Events, 3)

		assert.Equal(t, "branch-b", branchBVuln.AssetVersionName)
		assert.Equal(t, models.VulnStateAccepted, branchBVuln.State)
		assert.Len(t, branchBVuln.Events, 3)

		branchBEvents := branchBVuln.Events

		var copiedDetectedEvent models.VulnEvent
		var copiedAcceptedEvent models.VulnEvent
		var copiedCommentEvent models.VulnEvent

		for _, event := range branchBEvents {
			switch event.Type {
			case models.EventTypeDetected:
				copiedDetectedEvent = event
			case models.EventTypeAccepted:
				copiedAcceptedEvent = event
			case models.EventTypeComment:
				copiedCommentEvent = event
			}
		}

		assert.NotEmpty(t, copiedDetectedEvent)
		assert.Equal(t, models.EventTypeDetected, copiedDetectedEvent.Type)
		assert.Equal(t, branchBVuln.CalculateHash(), copiedDetectedEvent.VulnID)

		assert.NotEmpty(t, copiedAcceptedEvent)
		assert.Equal(t, models.EventTypeAccepted, copiedAcceptedEvent.Type)
		assert.Equal(t, "test-user", copiedAcceptedEvent.UserID)
		assert.Equal(t, "Accepting this vulnerability for testing lifecycle management", *copiedAcceptedEvent.Justification)
		assert.Equal(t, branchBVuln.CalculateHash(), copiedAcceptedEvent.VulnID)

		assert.NotEmpty(t, copiedCommentEvent)
		assert.Equal(t, models.EventTypeComment, copiedCommentEvent.Type)
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
		assert.Equal(t, models.VulnStateAccepted, branchCVuln.State)
		assert.Len(t, branchCVuln.Events, 3)
	})

	t.Run("should handle false positive events in lifecycle management", func(t *testing.T) {

		dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
		vulns, _ := dependencyVulnRepository.GetByAssetID(nil, asset.ID)
		for _, vuln := range vulns {
			db.Delete(&vuln)
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

		fpEvent := models.NewFalsePositiveEvent(branchDVuln.ID, branchDVuln.GetType(), "test-user", "This is a false positive", models.ComponentNotPresent, "lifecycle-artifact-fp")
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

		assert.Equal(t, models.VulnStateFalsePositive, branchEVuln.State)
		assert.Len(t, branchEVuln.Events, 2)

		var copiedFPEvent models.VulnEvent
		for _, event := range branchEVuln.Events {
			if event.Type == models.EventTypeFalsePositive {
				copiedFPEvent = event
				break
			}
		}

		assert.NotEmpty(t, copiedFPEvent)
		assert.Equal(t, "This is a false positive", *copiedFPEvent.Justification)
	})
}

func TestFirstPartyVulnerabilityLifecycleManagement(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, _ := initHTTPController(t, db, false)

	app := echo.New()
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("test-user")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)

	t.Run("should copy all events when first party vulnerability is found on different branches", func(t *testing.T) {

		vulns, _ := firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
		for _, vuln := range vulns {
			db.Delete(&vuln)
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
		assert.Equal(t, models.VulnStateOpen, branchAVuln.State)

		acceptedEvent := models.NewAcceptedEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Accepted for lifecycle testing")
		err = firstPartyVulnRepository.ApplyAndSave(nil, &branchAVuln, &acceptedEvent)
		assert.Nil(t, err)

		commentEvent := models.NewCommentEvent(branchAVuln.ID, branchAVuln.GetType(), "test-user", "Test comment for lifecycle verification")
		err = firstPartyVulnRepository.ApplyAndSave(nil, &branchAVuln, &commentEvent)
		assert.Nil(t, err)

		vulns, err = firstPartyVulnRepository.GetByAssetID(nil, asset.ID)
		assert.Nil(t, err)
		branchAVuln = vulns[0]
		assert.Equal(t, models.VulnStateAccepted, branchAVuln.State)
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
		assert.Equal(t, models.VulnStateAccepted, branchBVuln.State)
		assert.Len(t, branchBVuln.Events, 3)

		var copiedAcceptedEvent, copiedCommentEvent models.VulnEvent
		for _, event := range branchBVuln.Events {
			switch event.Type {
			case models.EventTypeAccepted:
				copiedAcceptedEvent = event
			case models.EventTypeComment:
				copiedCommentEvent = event
			}
		}

		assert.NotEmpty(t, copiedAcceptedEvent.ID)
		assert.Equal(t, models.EventTypeAccepted, copiedAcceptedEvent.Type)
		assert.Equal(t, "test-user", copiedAcceptedEvent.UserID)
		assert.Equal(t, "Accepted for lifecycle testing", *copiedAcceptedEvent.Justification)
		assert.Equal(t, branchBVuln.CalculateHash(), copiedAcceptedEvent.VulnID)

		assert.NotEmpty(t, copiedCommentEvent.ID)
		assert.Equal(t, models.EventTypeComment, copiedCommentEvent.Type)
		assert.Equal(t, "test-user", copiedCommentEvent.UserID)
		assert.Equal(t, "Test comment for lifecycle verification", *copiedCommentEvent.Justification)
		assert.Equal(t, branchBVuln.CalculateHash(), copiedCommentEvent.VulnID)
	})
}

func TestTicketHandling(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")

	controller, gitlabClientFacade := initHTTPController(t, db, true)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	gitlabIntegration := models.GitLabIntegration{
		AccessToken: "access-token",
		GitLabURL:   "https://gitlab.com",
		OrgID:       org.ID,
	}
	err := db.Create(&gitlabIntegration).Error
	assert.Nil(t, err)

	t.Run("should open tickets for vulnerabilities if the risk threshold is exceeded", func(t *testing.T) {

		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
		asset.RepositoryID = utils.Ptr(fmt.Sprintf("gitlab:%s:123", gitlabIntegration.ID))
		err = db.Save(&asset).Error
		assert.Nil(t, err)

		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
		}
		err = db.Save(&cve).Error
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

		err := db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				AssetVersionName: "main",
				State:            models.VulnStateOpen,
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
		err := db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				AssetVersionName: "main",
				State:            models.VulnStateOpen,
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
		err = db.Save(&cve).Error
		assert.Nil(t, err)

		if err := db.Delete(&models.DependencyVuln{}, "cve_id = ?", "CVE-2025-46569").Error; err != nil {
			panic(err)
		}
		// create a vulnerability with an accepted state
		vuln := models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateAccepted,
				AssetVersionName: "main",
				AssetID:          asset.ID,
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
			},
		}
		err = db.Clauses(clause.OnConflict{
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
		var response scan.ScanResponse
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
				State:            models.VulnStateOpen,
				AssetVersionName: "main",
				AssetID:          asset.ID,
				TicketID:         nil,
			},
			Artifacts: []models.Artifact{
				{ArtifactName: "artifact-4", AssetVersionName: "main", AssetID: asset.ID},
			},
		}
		err = db.Clauses(clause.OnConflict{
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
}

func createCVE2025_46569(db core.DB) {
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

func sbomWithVulnerability() io.Reader {
	content := getSBOMWithVulnerabilityContent()
	return bytes.NewReader(content)
}

func sbomWithoutVulnerability() io.Reader {
	content := getSBOMWithoutVulnerabilityContent()
	return bytes.NewReader(content)
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

func initHTTPController(t *testing.T, db core.DB, mockDepsDev bool) (*scan.HTTPController, *mocks.GitlabClientFacade) {
	// there are a lot of repositories and services that need to be initialized...
	clientfactory, client := integration_tests.NewTestClientFactory(t)

	repositories.NewExploitRepository(db)
	// mock the depsDevService to avoid any external calls during tests
	depsDevService := mocks.NewDepsDevService(t)
	if mockDepsDev {
		depsDevService.On("GetVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(common.DepsDevVersionResponse{}, nil)
	}

	controller := inithelper.CreateHTTPController(db, gitlabint.NewGitLabOauth2Integrations(db), mocks.NewRBACProvider(t), clientfactory, depsDevService)
	// do not use concurrency in this test, because we want to test the ticket creation
	controller.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()
	return controller, client
}
