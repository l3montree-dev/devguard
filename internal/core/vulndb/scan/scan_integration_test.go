package scan_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
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

func TestScanning(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	os.Setenv("OSI_LICENSES_API", "https://opensource.org/api/license/")
	controller, _ := initHTTPController(t, db)

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
		req.Header.Set("X-Scanner", "scanner-1")
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

	t.Run("should add the scanner id, if the vulnerability is found with another scanner", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		// reopen file
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-2")
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
		assert.Equal(t, 0, response.AmountOpened) // already detected with other scanner
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
		// the scanner id should be updated
		assert.Equal(t, "scanner-1 scanner-2", response.DependencyVulns[0].ScannerIDs)
	})

	t.Run("should only return vulnerabilities, which are found by the current scanner", func(t *testing.T) {
		// scan the sbom without the vulnerability
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-3")
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

	t.Run("should return amount of closed 1, if the vulnerability is not detected by ANY scanner anymore", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
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
		assert.Equal(t, 0, response.AmountClosed)  // the vulnerability was not closed - still found by scanner 2
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned

		sbomFile = sbomWithoutVulnerability()
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-2")
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

	t.Run("should respect, if the vulnerability is just found AGAIN on a different branch then the default branch", func(t *testing.T) {
		// if we find a vuln A on the default branch. Then we accept vuln A.
		// now we find vuln A on a different branch. This vuln should be accepted as well.

		// create a vulnerability with an accepted state on the default branch in the database
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
		req.Header.Set("X-Scanner", "scanner-4")
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

		// expect the events to be copied as well
		// the last event should be of type detected on different branch - the event before should be accepted with the same message
		var newVuln models.DependencyVuln
		for _, v := range vulns {
			if v.AssetVersionName == "some-other-branch" {
				newVuln = v
			}
		}

		assert.NotEmpty(t, newVuln.Events)
		lastTwoEvents := newVuln.Events[len(newVuln.Events)-2:]

		// we can not really rely on the created_at since the events are created in the same second
		// nevertheless - one has to be the accepted event and the other the detected on different branch event
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

func TestTicketHandling(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	os.Setenv("OSI_LICENSES_API", "https://opensource.org/api/license/")
	controller, gitlabClientFacade := initHTTPController(t, db)

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

	// create a gitlab integration for this org
	gitlabIntegration := models.GitLabIntegration{
		AccessToken: "access-token",
		GitLabURL:   "https://gitlab.com",
		OrgID:       org.ID,
	}
	err := db.Create(&gitlabIntegration).Error
	assert.Nil(t, err)

	t.Run("should open tickets for vulnerabilities if the risk threshold is exceeded", func(t *testing.T) {
		// update the asset to have a cvss threshold of 7
		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
		asset.RepositoryID = utils.Ptr(fmt.Sprintf("gitlab:%s:123", gitlabIntegration.ID))
		err = db.Save(&asset).Error
		assert.Nil(t, err)

		// update the cve to exceed this threshold
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
		req.Header.Set("X-Scanner", "scanner-4")

		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		// expect there should be a ticket created for the vulnerability
		gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{
			IID: 456,
		}, nil, nil).Once()
		gitlabClientFacade.On("CreateIssueComment", mock.Anything, 123, 456, &gitlab.CreateIssueNoteOptions{
			Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
		}).Return(nil, nil, nil).Once()
		// now we expect, that the controller creates a ticket for that vulnerability
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
				ScannerIDs:       "scanner-4",
				State:            models.VulnStateOpen,
				AssetID:          asset.ID,
				TicketID:         utils.Ptr("gitlab:abc/789"),
			},
		}).Error
		assert.Nil(t, err)

		// scan the sbom with the vulnerability again
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		// expect there should be a ticket closed for the vulnerability
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
				ScannerIDs:       "some-other-scanner scanner-4",
				State:            models.VulnStateOpen,
				AssetID:          asset.ID,
				TicketID:         utils.Ptr("gitlab:abc/789"),
			},
		}).Error
		assert.Nil(t, err)

		// scan the sbom with the vulnerability again
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")
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
				ScannerIDs:       "scanner-4",
				AssetVersionName: "main",
				AssetID:          asset.ID,
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
		req.Header.Set("X-Scanner", "scanner-4")
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
				ScannerIDs:       "scanner-4",
				AssetVersionName: "main",
				AssetID:          asset.ID,
				TicketID:         nil,
			},
		}
		err = db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&vuln).Error
		// find the vulnerability again - so that the create issue function is triggered
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-component")
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

		// check the third argument of the CreateIssue call
		createIssueOptions := gitlabClientFacade.Calls[0].Arguments[2].(*gitlab.CreateIssueOptions)

		assert.Equal(t, "CVE-2025-46569 found in golang/github.com/open-policy-agent/opa@v0.68.0", *createIssueOptions.Title)
		assert.Equal(t,
			"## CVE-2025-46569 found in golang/github.com/open-policy-agent/opa@v0.68.0 \n> [!important] \n> **Risk**: `0.00 (Unknown)`\n> **CVSS**: `0.0` \n### Description\n\n### Affected component \nThe vulnerability is in `pkg:golang/github.com/open-policy-agent/opa@v0.68.0`, detected by `scanner-4`, `scanner-component`.\n### Recommended fix\nNo fix is available.\n\n### Additional guidance for mitigating vulnerabilities\nVisit our guides on [devguard.org](https://devguard.org/risk-mitigation-guides/software-composition-analysis)\n\n<details>\n\n<summary>See more details...</summary>\n\n### Path to component\n```mermaid \n %%{init: { 'theme':'base', 'themeVariables': {\n'primaryColor': '#F3F3F3',\n'primaryTextColor': '#0D1117',\n'primaryBorderColor': '#999999',\n'lineColor': '#999999',\n'secondaryColor': '#ffffff',\n'tertiaryColor': '#ffffff'\n} }}%%\n flowchart TD\nroot([\"root\"]) --- scanner_4([\"scanner-4\"])\nscanner_4([\"scanner-4\"]) --- go_mod([\"go.mod\"])\ngo_mod([\"go.mod\"]) --- github_com_l3montree_dev_devguard_test([\"github.com/l3montree-dev/devguard-test\"])\ngithub_com_l3montree_dev_devguard_test([\"github.com/l3montree-dev/devguard-test\"]) --- github_com_open_policy_agent_opa([\"github.com/open-policy-agent/opa\"])\nroot([\"root\"]) --- scanner_component([\"scanner-component\"])\nscanner_component([\"scanner-component\"]) --- go_mod([\"go.mod\"])\n\nclassDef default stroke-width:2px\n```\n| Risk Factor  | Value | Description | \n| ---- | ----- | ----------- | \n| Vulnerability Depth | `0` | The vulnerability is in a direct dependency of your project. | \n| EPSS | `0.00 %` | The exploit probability is very low. The vulnerability is unlikely to be exploited in the next 30 days. | \n| EXPLOIT | `Not available` | We did not find any exploit available. Neither in GitHub repositories nor in the Exploit-Database. There are no script kiddies exploiting this vulnerability. | \n| CVSS-BE | `0.0` |  | \n| CVSS-B | `0.0` |  | \n\nMore details can be found in [DevGuard](FRONTEND_URL/test-org/projects/test-project/assets/test-asset/refs/main/dependency-risks/"+vuln.ID+")\n\n</details>\n\n\n--- \n### Interact with this vulnerability\nYou can use the following slash commands to interact with this vulnerability:\n\n#### 👍   Reply with this to acknowledge and accept the identified risk.\n```text\n/accept I accept the risk of this vulnerability, because ...\n```\n\n#### ⚠️ Mark the risk as false positive: Use one of these commands if you believe the reported vulnerability is not actually a valid issue.\n```text\n/component-not-present The vulnerable component is not included in the artifact.\n```\n```text\n/vulnerable-code-not-present The component is present, but the vulnerable code is not included or compiled.\n```\n```text\n/vulnerable-code-not-in-execute-path The vulnerable code exists, but is never executed at runtime.\n```\n```text\n/vulnerable-code-cannot-be-controlled-by-adversary Built-in protections prevent exploitation of this vulnerability.\n```\n```text\n/inline-mitigations-already-exist The vulnerable code cannot be controlled or influenced by an attacker.\n```\n\n#### 🔁  Reopen the risk: Use this command to reopen a previously closed or accepted vulnerability.\n```text\n/reopen ... \n```\n", *createIssueOptions.Description)
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

func sbomWithVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-with-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func sbomWithoutVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-without-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func initHTTPController(t *testing.T, db core.DB) (*scan.HTTPController, *mocks.GitlabClientFacade) {
	// there are a lot of repositories and services that need to be initialized...
	clientfactory, client := integration_tests.NewTestClientFactory(t)

	repositories.NewExploitRepository(db)
	// mock the depsDevService to avoid any external calls during tests
	depsDevService := mocks.NewDepsDevService(t)
	depsDevService.On("GetVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(common.DepsDevVersionResponse{}, nil)

	controller := inithelper.CreateHTTPController(db, gitlabint.NewGitLabOauth2Integrations(db), mocks.NewRBACProvider(t), clientfactory, depsDevService)
	// do not use concurrency in this test, because we want to test the ticket creation
	controller.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()
	return controller, client
}
