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

package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// complianceScope is an org with a project, a subproject and an asset version inside the subproject.
type complianceScope struct {
	org          models.Org
	project      models.Project
	subproject   models.Project
	asset        models.Asset
	assetVersion models.AssetVersion
}

func newComplianceScope(t *testing.T, f *TestFixture, name string) complianceScope {
	t.Helper()
	org := f.CreateOrg(name)
	project := f.CreateProject(org.ID, name+"-project")
	subproject := models.Project{Name: name + "-subproject", Slug: name + "-subproject", OrganizationID: org.ID, ParentID: &project.ID}
	require.NoError(t, f.DB.Create(&subproject).Error)
	asset := f.CreateAsset(subproject.ID, name+"-asset")
	assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
	return complianceScope{org: org, project: project, subproject: subproject, asset: asset, assetVersion: assetVersion}
}

type testControl struct {
	id    string
	title string
	prose string
}

func catalogJSON(t *testing.T, title string, controls ...testControl) []byte {
	t.Helper()
	oscalControls := make([]map[string]any, 0, len(controls))
	for _, c := range controls {
		oscalControls = append(oscalControls, map[string]any{
			"id":    c.id,
			"title": c.title,
			"parts": []map[string]any{{"id": c.id + "_stm", "name": "statement", "prose": c.prose}},
		})
	}
	data, err := json.Marshal(map[string]any{
		"catalog": map[string]any{
			"uuid":     uuid.NewString(),
			"metadata": map[string]any{"title": title, "last-modified": "2026-01-01T00:00:00Z", "version": "1.0", "oscal-version": "1.1.3"},
			"controls": oscalControls,
		},
	})
	require.NoError(t, err)
	return data
}

func componentDefinitionJSON(t *testing.T, title string, componentUUID string, source string, controlIDs ...string) []byte {
	t.Helper()
	requirements := make([]map[string]any, 0, len(controlIDs))
	for _, id := range controlIDs {
		requirements = append(requirements, map[string]any{"uuid": uuid.NewString(), "control-id": id, "description": "implements " + id})
	}
	data, err := json.Marshal(map[string]any{
		"component-definition": map[string]any{
			"uuid":     uuid.NewString(),
			"metadata": map[string]any{"title": title, "last-modified": "2026-01-01T00:00:00Z", "version": "1.0", "oscal-version": "1.1.3"},
			"components": []map[string]any{{
				"uuid":        componentUUID,
				"type":        "software",
				"title":       "Branch Protection",
				"description": "Protected branches",
				"control-implementations": []map[string]any{{
					"uuid":                     uuid.NewString(),
					"source":                   source,
					"description":              "Implementation",
					"implemented-requirements": requirements,
				}},
			}},
		},
	})
	require.NoError(t, err)
	return data
}

var (
	controlGov1 = testControl{id: "GOV.1", title: "Governance", prose: "Define responsibilities."}
	controlGov2 = testControl{id: "GOV.2", title: "Review", prose: "Review the responsibilities."}
	controlOps1 = testControl{id: "OPS.1", title: "Operations", prose: "Encrypt data at rest."}
)

func listPostures(t *testing.T, f *TestFixture, s complianceScope, filter ...shared.FilterQuery) []dtos.CompliancePostureWithControl {
	t.Helper()
	paged, err := f.App.CompliancePostureService.GetForAllControlsPaged(context.Background(), nil, &s.assetVersion.ID, &s.asset.ID, &s.subproject.ID, s.org.ID, shared.PageInfo{Page: 1, PageSize: 100}, "", filter, nil)
	require.NoError(t, err)
	return paged.Data
}

func postureByControlID(t *testing.T, postures []dtos.CompliancePostureWithControl, controlID string) dtos.CompliancePostureWithControl {
	t.Helper()
	for _, p := range postures {
		if p.ControlID == controlID {
			return p
		}
	}
	require.Failf(t, "posture not found", "no posture for control %s", controlID)
	return dtos.CompliancePostureWithControl{}
}

func controlIDs(postures []dtos.CompliancePostureWithControl) []string {
	ids := make([]string, len(postures))
	for i, p := range postures {
		ids[i] = p.ControlID
	}
	return ids
}

func assertHTTPError(t *testing.T, err error, code int) {
	t.Helper()
	var httpErr *echo.HTTPError
	require.True(t, errors.As(err, &httpErr), "expected an echo.HTTPError, got %v", err)
	assert.Equal(t, code, httpErr.Code)
}

func setPostureState(t *testing.T, f *TestFixture, s complianceScope, controlHash string, eventType dtos.VulnEventType) {
	t.Helper()
	ctx := context.Background()
	posture := models.CompliancePosture{
		ControlHash:      controlHash,
		OrgID:            s.org.ID,
		ProjectID:        &s.subproject.ID,
		AssetID:          &s.asset.ID,
		AssetVersionID:   &s.assetVersion.ID,
		AssetVersionName: &s.assetVersion.Name,
		Vulnerability:    models.Vulnerability{State: dtos.VulnStateOpen},
	}
	posture.ID = posture.CalculateHash()
	created, err := f.App.CompliancePostureRepository.FindOrCreate(ctx, nil, posture)
	require.NoError(t, err)
	_, err = f.App.CompliancePostureService.UpdateCompliancePostureState(ctx, nil, "user", created, string(eventType), "done", "", nil)
	require.NoError(t, err)
}

func TestComplianceCatalogScopes(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()
		catalogs := f.App.ComplianceCatalogService

		t.Run("a catalog activated on the org is inherited by projects, subprojects and assets", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-inherit")
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, controlGov2)))

			for _, scope := range []struct {
				name      string
				projectID *uuid.UUID
				assetID   *uuid.UUID
			}{
				{"org", nil, nil},
				{"project", &s.project.ID, nil},
				{"subproject", &s.subproject.ID, nil},
				{"asset", &s.subproject.ID, &s.asset.ID},
			} {
				list, err := catalogs.ListCatalogs(ctx, nil, s.org.ID, scope.projectID, scope.assetID)
				require.NoError(t, err, scope.name)
				require.Len(t, list, 1, scope.name)
				assert.Equal(t, "Catalog A", list[0].Framework, scope.name)
				assert.Nil(t, list[0].ProjectID, scope.name)
				assert.Nil(t, list[0].AssetID, scope.name)
			}

			postures := listPostures(t, f, s)
			assert.ElementsMatch(t, []string{"GOV.1", "GOV.2"}, controlIDs(postures))
			gov1 := postureByControlID(t, postures, "GOV.1")
			assert.Equal(t, []string{"Catalog A"}, gov1.Frameworks)
			assert.Equal(t, []string{"Catalog A:GOV.1"}, gov1.FrameworkControlIDs)
			assert.NotEmpty(t, gov1.ControlHash)
		})

		t.Run("a catalog can only be deleted on the level it was activated on", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-delete")
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "Catalog A", catalogJSON(t, "Catalog A", controlGov1)))

			assertHTTPError(t, catalogs.DeleteCatalog(ctx, nil, s.org.ID, &s.project.ID, nil, "Catalog A"), http.StatusNotFound)
			assertHTTPError(t, catalogs.DeleteCatalog(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, "Catalog A"), http.StatusNotFound)

			require.NoError(t, catalogs.DeleteCatalog(ctx, nil, s.org.ID, nil, nil, "Catalog A"))
			assert.Empty(t, listPostures(t, f, s))
		})

		t.Run("a catalog activated on an asset does not apply to other assets", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-asset")
			otherAsset := f.CreateAsset(s.subproject.ID, "catalog-asset-other")

			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, "", catalogJSON(t, "Catalog A", controlGov1)))

			list, err := catalogs.ListCatalogs(ctx, nil, s.org.ID, &s.subproject.ID, &otherAsset.ID)
			require.NoError(t, err)
			assert.Empty(t, list)

			list, err = catalogs.ListCatalogs(ctx, nil, s.org.ID, &s.subproject.ID, nil)
			require.NoError(t, err)
			assert.Empty(t, list)

			list, err = catalogs.ListCatalogs(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID)
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, &s.asset.ID, list[0].AssetID)
		})

		t.Run("a control shared by two catalogs is listed once with both frameworks", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-shared")
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, controlGov2)))
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, &s.project.ID, nil, "", catalogJSON(t, "Catalog B", controlGov1, controlOps1)))

			postures := listPostures(t, f, s)
			assert.ElementsMatch(t, []string{"GOV.1", "GOV.2", "OPS.1"}, controlIDs(postures))
			gov1 := postureByControlID(t, postures, "GOV.1")
			assert.Equal(t, []string{"Catalog A", "Catalog B"}, gov1.Frameworks)
			assert.Equal(t, []string{"Catalog A:GOV.1", "Catalog B:GOV.1"}, gov1.FrameworkControlIDs)

			filtered := listPostures(t, f, s, shared.FilterQuery{Field: "framework", Operator: "is", FieldValue: "Catalog B"})
			assert.ElementsMatch(t, []string{"GOV.1", "OPS.1"}, controlIDs(filtered))
			filtered = listPostures(t, f, s, shared.FilterQuery{Field: "framework", Operator: "is not", FieldValue: "Catalog B"})
			assert.ElementsMatch(t, []string{"GOV.2"}, controlIDs(filtered))
			filtered = listPostures(t, f, s, shared.FilterQuery{Field: "framework", Operator: "ilike", FieldValue: "%catalog b%"})
			assert.ElementsMatch(t, []string{"GOV.1", "OPS.1"}, controlIDs(filtered))

			sorted, err := f.App.CompliancePostureService.GetForAllControlsPaged(ctx, nil, &s.assetVersion.ID, &s.asset.ID, &s.subproject.ID, s.org.ID, shared.PageInfo{Page: 1, PageSize: 100}, "", nil, []shared.SortQuery{{Field: "frameworks", Operator: "desc"}})
			require.NoError(t, err)
			require.Len(t, sorted.Data, 3)
			assert.Equal(t, "OPS.1", sorted.Data[0].ControlID, "only catalog B sorts after catalog A and catalog B")

			stats, err := f.App.CompliancePostureService.GetStatsForAllControls(ctx, nil, &s.assetVersion.ID, &s.asset.ID, &s.subproject.ID, s.org.ID, []shared.FilterQuery{{Field: "framework", Operator: "is not", FieldValue: "Catalog B"}})
			require.NoError(t, err)
			assert.Equal(t, int64(1), stats.Open)

			// the project does not see the catalog of the org twice and the org does not see the catalog of the project
			orgPostures, err := f.App.CompliancePostureService.GetForAllControlsPaged(ctx, nil, nil, nil, nil, s.org.ID, shared.PageInfo{Page: 1, PageSize: 100}, "", nil, nil)
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{"GOV.1", "GOV.2"}, controlIDs(orgPostures.Data))

			// deleting catalog A keeps the shared control because it still belongs to catalog B
			require.NoError(t, catalogs.DeleteCatalog(ctx, nil, s.org.ID, nil, nil, "Catalog A"))
			postures = listPostures(t, f, s)
			assert.ElementsMatch(t, []string{"GOV.1", "OPS.1"}, controlIDs(postures))
			assert.Equal(t, []string{"Catalog B"}, postureByControlID(t, postures, "GOV.1").Frameworks)
		})

		t.Run("re-uploading a catalog keeps the state of unchanged controls and drops removed controls", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-reupload")
			// controls are shared by all orgs with the same content, so use controls no other test uses
			controlGov1 := testControl{id: "GOV.1", title: "Governance", prose: "Define the responsibilities of the re-upload."}
			controlGov2 := testControl{id: "GOV.2", title: "Review", prose: "Review the responsibilities of the re-upload."}
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, controlGov2)))

			postures := listPostures(t, f, s)
			gov1Hash := postureByControlID(t, postures, "GOV.1").ControlHash
			gov2Hash := postureByControlID(t, postures, "GOV.2").ControlHash
			setPostureState(t, f, s, gov1Hash, dtos.EventTypeImplemented)
			setPostureState(t, f, s, gov2Hash, dtos.EventTypeImplemented)

			changedGov2 := controlGov2
			changedGov2.prose = "Review the responsibilities every year."
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, changedGov2, controlOps1)))

			postures = listPostures(t, f, s)
			assert.ElementsMatch(t, []string{"GOV.1", "GOV.2", "OPS.1"}, controlIDs(postures))

			gov1 := postureByControlID(t, postures, "GOV.1")
			assert.Equal(t, gov1Hash, gov1.ControlHash)
			assert.Equal(t, dtos.VulnStateImplemented, gov1.State)

			// a changed control is a new control, so its state starts over
			gov2 := postureByControlID(t, postures, "GOV.2")
			assert.NotEqual(t, gov2Hash, gov2.ControlHash)
			assert.NotEqual(t, dtos.VulnStateImplemented, gov2.State)

			var count int64
			require.NoError(t, f.DB.Model(&models.FrameworkControl{}).Where("control_hash = ?", gov2Hash).Count(&count).Error)
			assert.Zero(t, count, "the old version of GOV.2 belongs to no catalog anymore")
			require.NoError(t, f.DB.Model(&models.CompliancePosture{}).Where("control_hash = ?", gov2Hash).Count(&count).Error)
			assert.Zero(t, count, "the posture of the old version of GOV.2 is deleted with its control")
		})

		t.Run("the detail view only shows frameworks of the scope", func(t *testing.T) {
			s := newComplianceScope(t, f, "catalog-detail")
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1)))
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, "", catalogJSON(t, "Catalog B", controlGov1, controlOps1)))

			postures := listPostures(t, f, s)
			gov1Hash := postureByControlID(t, postures, "GOV.1").ControlHash
			ops1Hash := postureByControlID(t, postures, "OPS.1").ControlHash
			setPostureState(t, f, s, gov1Hash, dtos.EventTypeImplemented)

			posture, err := f.App.CompliancePostureService.GetForControl(ctx, nil, gov1Hash, &s.assetVersion.ID, &s.asset.ID, &s.subproject.ID, s.org.ID)
			require.NoError(t, err)
			assert.Equal(t, dtos.VulnStateImplemented, posture.State)
			assert.Len(t, posture.Events, 1)
			assert.Len(t, posture.FrameworkControl.ScopeFrameworks, 2)

			posture, err = f.App.CompliancePostureService.GetForControl(ctx, nil, gov1Hash, nil, nil, &s.project.ID, s.org.ID)
			require.NoError(t, err)
			require.Len(t, posture.FrameworkControl.ScopeFrameworks, 1)
			assert.Equal(t, "Catalog A", posture.FrameworkControl.ScopeFrameworks[0].Framework)
			assert.Equal(t, dtos.VulnStateOpen, posture.State, "the state of the asset version does not apply to the project")

			_, err = f.App.CompliancePostureService.GetForControl(ctx, nil, ops1Hash, nil, nil, &s.project.ID, s.org.ID)
			assert.True(t, shared.IsNotFound(err), "OPS.1 is only activated on the asset")
		})
	})
}

func TestComplianceComponentDefinitionScopes(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()
		catalogs := f.App.ComplianceCatalogService
		definitions := f.App.ComplianceComponentDefinitionService
		components := f.App.ComplianceComponentRepository

		t.Run("a component definition uploaded on the org is inherited and covers its controls", func(t *testing.T) {
			s := newComplianceScope(t, f, "components-inherit")
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, controlGov2)))
			require.NoError(t, definitions.SaveComponentDefinition(ctx, nil, s.org.ID, nil, nil, "", componentDefinitionJSON(t, "Components", uuid.NewString(), "Catalog A", "GOV.1")))

			list, err := components.ListAll(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, nil)
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, "Branch Protection", list[0].Title)
			require.NotNil(t, list[0].ComponentDefinition)
			assert.Equal(t, "Components", *list[0].ComponentDefinition)
			assert.Nil(t, list[0].ProjectID)
			require.Len(t, list[0].ImplementedControls, 1)
			assert.Equal(t, "Catalog A:GOV.1", list[0].ImplementedControls[0].FrameworkControlID)

			details, err := components.GetDetails(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, list[0].ID)
			require.NoError(t, err)
			assert.Equal(t, list[0].ID, details.ID)

			covered := listPostures(t, f, s, shared.FilterQuery{Field: "has_component_coverage", Operator: "is", FieldValue: "true"})
			assert.Equal(t, []string{"GOV.1"}, controlIDs(covered))
			uncovered := listPostures(t, f, s, shared.FilterQuery{Field: "has_component_coverage", Operator: "is", FieldValue: "false"})
			assert.Equal(t, []string{"GOV.2"}, controlIDs(uncovered))
		})

		t.Run("a component definition can only be deleted on the level it was uploaded on", func(t *testing.T) {
			s := newComplianceScope(t, f, "components-delete")
			require.NoError(t, definitions.SaveComponentDefinition(ctx, nil, s.org.ID, nil, nil, "", componentDefinitionJSON(t, "Components", uuid.NewString(), "Catalog A", "GOV.1")))

			assertHTTPError(t, definitions.DeleteComponentDefinition(ctx, nil, s.org.ID, &s.project.ID, nil, "Components"), http.StatusNotFound)

			require.NoError(t, definitions.DeleteComponentDefinition(ctx, nil, s.org.ID, nil, nil, "Components"))
			list, err := components.ListAll(ctx, nil, s.org.ID, &s.project.ID, nil, nil)
			require.NoError(t, err)
			assert.Empty(t, list)
		})

		t.Run("a component of another asset is not visible", func(t *testing.T) {
			s := newComplianceScope(t, f, "components-asset")
			otherAsset := f.CreateAsset(s.subproject.ID, "components-asset-other")
			require.NoError(t, definitions.SaveComponentDefinition(ctx, nil, s.org.ID, &s.subproject.ID, &otherAsset.ID, "", componentDefinitionJSON(t, "Components", uuid.NewString(), "Catalog A", "GOV.1")))

			list, err := components.ListAll(ctx, nil, s.org.ID, &s.subproject.ID, &otherAsset.ID, nil)
			require.NoError(t, err)
			require.Len(t, list, 1)

			list, err = components.ListAll(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, nil)
			require.NoError(t, err)
			assert.Empty(t, list)

			_, err = components.GetDetails(ctx, nil, s.org.ID, &s.subproject.ID, &s.asset.ID, list0ID(t, f, s.org.ID, &s.subproject.ID, &otherAsset.ID))
			assert.True(t, shared.IsNotFound(err))
		})

		t.Run("re-uploading a component definition keeps the component and its statements", func(t *testing.T) {
			s := newComplianceScope(t, f, "components-reupload")
			componentUUID := uuid.NewString()
			require.NoError(t, catalogs.SaveCatalog(ctx, nil, s.org.ID, nil, nil, "", catalogJSON(t, "Catalog A", controlGov1, controlGov2)))
			require.NoError(t, definitions.SaveComponentDefinition(ctx, nil, s.org.ID, nil, nil, "", componentDefinitionJSON(t, "Components", componentUUID, "Catalog A", "GOV.1", "GOV.2")))

			componentID := list0ID(t, f, s.org.ID, nil, nil)
			postures := listPostures(t, f, s)
			gov1Statement := createStatement(t, f, s, postureByControlID(t, postures, "GOV.1").ControlHash, componentID, "Catalog A:GOV.1")
			gov2Statement := createStatement(t, f, s, postureByControlID(t, postures, "GOV.2").ControlHash, componentID, "Catalog A:GOV.2")

			// GOV.2 is not implemented anymore
			require.NoError(t, definitions.SaveComponentDefinition(ctx, nil, s.org.ID, nil, nil, "", componentDefinitionJSON(t, "Components", componentUUID, "Catalog A", "GOV.1")))

			assert.Equal(t, componentID, list0ID(t, f, s.org.ID, nil, nil), "the component keeps its id")

			var count int64
			require.NoError(t, f.DB.Model(&models.ComplianceComponentImplementsControlStatement{}).Where("id = ?", gov1Statement.ID).Count(&count).Error)
			assert.Equal(t, int64(1), count, "the statement of a control which is still implemented is kept")
			require.NoError(t, f.DB.Model(&models.ComplianceComponentImplementsControlStatement{}).Where("id = ?", gov2Statement.ID).Count(&count).Error)
			assert.Zero(t, count, "the statement of a control which is not implemented anymore is deleted")
		})
	})
}

func list0ID(t *testing.T, f *TestFixture, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) uuid.UUID {
	t.Helper()
	list, err := f.App.ComplianceComponentRepository.ListAll(context.Background(), nil, orgID, projectID, assetID, nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	return list[0].ID
}

func createStatement(t *testing.T, f *TestFixture, s complianceScope, controlHash string, componentID uuid.UUID, frameworkControlID string) *models.ComplianceComponentImplementsControlStatement {
	t.Helper()
	ctx := context.Background()
	posture := models.CompliancePosture{
		ControlHash:      controlHash,
		OrgID:            s.org.ID,
		ProjectID:        &s.subproject.ID,
		AssetID:          &s.asset.ID,
		AssetVersionID:   &s.assetVersion.ID,
		AssetVersionName: &s.assetVersion.Name,
	}
	posture.ID = posture.CalculateHash()
	created, err := f.App.CompliancePostureRepository.FindOrCreate(ctx, nil, posture)
	require.NoError(t, err)
	statement, err := f.App.ComplianceComponentRepository.CreateStatement(ctx, nil, models.ComplianceComponentImplementsControlStatement{
		CompliancePostureID:   created.ID,
		ComplianceComponentID: componentID,
		FrameworkControlID:    frameworkControlID,
		ImplementationStatus:  "implemented",
		Description:           fmt.Sprintf("statement for %s", frameworkControlID),
	})
	require.NoError(t, err)
	return statement
}
