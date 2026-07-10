// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

const testProviderID = "k8s-devguard-image-inventory"

func setupExternalSubprojectContext(t *testing.T, f *TestFixture, ctx shared.Context, org models.Org, project models.Project) {
	t.Helper()
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetProviderID(ctx, testProviderID)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))
	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Return("test-user-id").Maybe()
	shared.SetSession(ctx, session)
}

func TestHandleExternalSubprojectRequestUpdate(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, parentProject, _, _ := f.CreateOrgProjectAssetAndVersion()

		sbomBytes, err := os.ReadFile("testdata/empty-sbom.json")
		assert.NoError(t, err)

		app := echo.New()

		t.Run("should create project, asset, asset version and artifact on verb=update", func(t *testing.T) {
			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "update",
				ProjectExternalEntityID: "group-1",
				ProjectName:             "Group 1",
				AssetExternalEntityID:   "repo-1",
				AssetName:               "repo-1",
				AssetVersionName:        "main",
				Artifact:                "nginx:latest",
				Sbom:                    json.RawMessage(sbomBytes),
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err := f.App.ProjectController.HandleExternalSubprojectRequest(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			// project was created
			var createdProject models.Project
			assert.NoError(t, f.DB.Where("external_entity_id = ? AND external_entity_provider_id = ?", "group-1", testProviderID).First(&createdProject).Error)
			assert.Equal(t, "Group 1", createdProject.Name)

			// asset was created under that project
			var createdAsset models.Asset
			assert.NoError(t, f.DB.Where("external_entity_id = ? AND project_id = ?", "repo-1", createdProject.ID).First(&createdAsset).Error)

			// asset version was created
			var createdVersion models.AssetVersion
			assert.NoError(t, f.DB.Where("asset_id = ? AND name = ?", createdAsset.ID, "main").First(&createdVersion).Error)

			// artifact was created
			var createdArtifact models.Artifact
			assert.NoError(t, f.DB.Where("asset_id = ? AND artifact_name = ? AND asset_version_name = ?", createdAsset.ID, "nginx:latest", "main").First(&createdArtifact).Error)
		})

		t.Run("should create sub-project when SubProjectExternalEntityID is set", func(t *testing.T) {
			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                       "update",
				ProjectExternalEntityID:    "group-2",
				ProjectName:                "Group 2",
				SubProjectExternalEntityID: "subgroup-2",
				SubProjectName:             "Subgroup 2",
				AssetExternalEntityID:      "repo-2",
				AssetName:                  "repo-2",
				AssetVersionName:           "main",
				Artifact:                   "app:latest",
				Sbom:                       json.RawMessage(sbomBytes),
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err := f.App.ProjectController.HandleExternalSubprojectRequest(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			var project models.Project
			assert.NoError(t, f.DB.Where("external_entity_id = ? AND external_entity_provider_id = ?", "group-2", testProviderID).First(&project).Error)

			var subProject models.Project
			assert.NoError(t, f.DB.Where("external_entity_id = ? AND parent_id = ?", "subgroup-2", project.ID).First(&subProject).Error)
			assert.Equal(t, "Subgroup 2", subProject.Name)

			var asset models.Asset
			assert.NoError(t, f.DB.Where("external_entity_id = ? AND project_id = ?", "repo-2", subProject.ID).First(&asset).Error)
		})

		t.Run("should return 400 when sbom is missing on verb=update", func(t *testing.T) {
			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "update",
				ProjectExternalEntityID: "group-3",
				ProjectName:             "Group 3",
				AssetExternalEntityID:   "repo-3",
				AssetName:               "repo-3",
				AssetVersionName:        "main",
				Artifact:                "app:latest",
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err := f.App.ProjectController.HandleExternalSubprojectRequest(ctx)
			assert.Error(t, err)
			httpErr, ok := err.(*echo.HTTPError)
			assert.True(t, ok)
			assert.Equal(t, 400, httpErr.Code)
		})
	})
}

func TestHandleExternalSubprojectRequestDelete(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, parentProject, _, _ := f.CreateOrgProjectAssetAndVersion()

		sbomBytes, err := os.ReadFile("testdata/empty-sbom.json")
		assert.NoError(t, err)

		app := echo.New()

		createEntry := func(projectExtID, assetExtID, versionName, artifactName string) {
			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "update",
				ProjectExternalEntityID: projectExtID,
				ProjectName:             projectExtID,
				AssetExternalEntityID:   assetExtID,
				AssetName:               assetExtID,
				AssetVersionName:        versionName,
				Artifact:                artifactName,
				Sbom:                    json.RawMessage(sbomBytes),
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)
			assert.NoError(t, f.App.ProjectController.HandleExternalSubprojectRequest(ctx))
		}

		t.Run("should delete artifact and cascade to asset/version/project when last", func(t *testing.T) {
			createEntry("del-group-1", "del-repo-1", "main", "del-app:latest")

			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "delete",
				ProjectExternalEntityID: "del-group-1",
				AssetExternalEntityID:   "del-repo-1",
				AssetVersionName:        "main",
				Artifact:                "del-app:latest",
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err = f.App.ProjectController.HandleExternalSubprojectRequest(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			// artifact should be gone
			var artifact models.Artifact
			err = f.DB.Where("artifact_name = ?", "del-app:latest").First(&artifact).Error
			assert.Error(t, err)
		})

		t.Run("should keep asset version when other artifacts still reference it", func(t *testing.T) {
			createEntry("del-group-2", "del-repo-2", "main", "artifact-a:latest")
			createEntry("del-group-2", "del-repo-2", "main", "artifact-b:latest")

			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "delete",
				ProjectExternalEntityID: "del-group-2",
				AssetExternalEntityID:   "del-repo-2",
				AssetVersionName:        "main",
				Artifact:                "artifact-a:latest",
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err = f.App.ProjectController.HandleExternalSubprojectRequest(ctx)
			assert.NoError(t, err)

			// asset version should still exist because artifact-b still references it
			var version models.AssetVersion
			err = f.DB.Joins("JOIN assets ON assets.id = asset_versions.asset_id").
				Where("assets.external_entity_id = ? AND asset_versions.name = ?", "del-repo-2", "main").
				First(&version).Error
			assert.NoError(t, err)
		})
	})
}

func TestListExternalSubprojects(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, parentProject, _, _ := f.CreateOrgProjectAssetAndVersion()

		sbomBytes, err := os.ReadFile("testdata/empty-sbom.json")
		assert.NoError(t, err)

		app := echo.New()

		createEntry := func(projectExtID, projectName, assetExtID, assetName, versionName, artifactName string) {
			body := dtos.ExternalSubprojectRequestDTO{
				Verb:                    "update",
				ProjectExternalEntityID: projectExtID,
				ProjectName:             projectName,
				AssetExternalEntityID:   assetExtID,
				AssetName:               assetName,
				AssetVersionName:        versionName,
				Artifact:                artifactName,
				Sbom:                    json.RawMessage(sbomBytes),
			}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/external/"+testProviderID, bytes.NewBuffer(b))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)
			assert.NoError(t, f.App.ProjectController.HandleExternalSubprojectRequest(ctx))
		}

		createEntry("list-group-1", "List Group 1", "list-repo-1", "list-repo-1", "main", "app:v1")
		createEntry("list-group-1", "List Group 1", "list-repo-1", "list-repo-1", "main", "sidecar:v1")
		createEntry("list-group-2", "List Group 2", "list-repo-2", "list-repo-2", "v1.0", "app:v1")

		t.Run("should return all projects with their assets and artifacts", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/external/"+testProviderID, nil)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			setupExternalSubprojectContext(t, f, ctx, org, parentProject)

			err := f.App.ProjectController.ListExternalSubprojects(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			var result []dtos.ProjectExternalEntityTree
			assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))

			assert.Len(t, result, 2)

			// find list-group-1
			var group1 *dtos.ProjectExternalEntityTree
			for i := range result {
				if result[i].ProjectExternalEntityID == "list-group-1" {
					group1 = &result[i]
				}
			}
			assert.NotNil(t, group1)
			assert.Len(t, group1.Assets, 1)
			assert.Len(t, group1.Assets[0].AssetVersions, 1)
			assert.ElementsMatch(t, []string{"app:v1", "sidecar:v1"}, group1.Assets[0].AssetVersions[0].Artifacts)
		})

		t.Run("should return empty list when no external projects exist for provider", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/external/unknown-provider", nil)
			rec := httptest.NewRecorder()
			ctx := app.NewContext(req, rec)
			shared.SetOrg(ctx, org)
			shared.SetProject(ctx, parentProject)
			shared.SetProviderID(ctx, "unknown-provider")
			session := mocks.NewAuthSession(t)
			session.On("GetUserID").Return("test-user-id").Maybe()
			shared.SetSession(ctx, session)

			err := f.App.ProjectController.ListExternalSubprojects(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, rec.Code)

			var result []dtos.ProjectExternalEntityTree
			assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			assert.Empty(t, result)
		})
	})
}
