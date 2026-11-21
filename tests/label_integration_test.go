// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type labelFixture struct {
	orgA, orgB       models.Org
	p1, p2, pB       models.Project
	a1, a2, a3, aB   models.Asset
	artifactOnAsset1 models.Artifact
	labels           map[string]models.Label
	repo             *repositories.LabelRepository
	service          *services.LabelService
	controller       *controllers.LabelController
	db               shared.DB
}

func newLabelFixture(t *testing.T, db shared.DB) *labelFixture {
	t.Helper()
	f := &labelFixture{db: db, labels: map[string]models.Label{}}

	suffix := uuid.NewString()[:8]
	mustCreate := func(v any) {
		require.NoError(t, db.Create(v).Error)
	}
	newOrg := func(name string) models.Org {
		o := models.Org{Name: name, Slug: name + "-" + suffix}
		mustCreate(&o)
		return o
	}
	newProject := func(org models.Org, name string) models.Project {
		p := models.Project{Name: name, Slug: name + "-" + suffix, OrganizationID: org.ID}
		mustCreate(&p)
		return p
	}
	newAsset := func(p models.Project, name string) models.Asset {
		a := models.Asset{Name: name, Slug: name + "-" + suffix, ProjectID: p.ID}
		mustCreate(&a)
		return a
	}

	f.orgA, f.orgB = newOrg("org-a"), newOrg("org-b")
	f.p1, f.p2, f.pB = newProject(f.orgA, "p1"), newProject(f.orgA, "p2"), newProject(f.orgB, "pb")
	f.a1, f.a2, f.a3, f.aB = newAsset(f.p1, "a1"), newAsset(f.p1, "a2"), newAsset(f.p2, "a3"), newAsset(f.pB, "ab")

	av := models.AssetVersion{Name: "main", AssetID: f.a1.ID, DefaultBranch: true, Slug: "main", Type: "branch"}
	mustCreate(&av)
	f.artifactOnAsset1 = models.Artifact{ArtifactName: "artifact", AssetVersionID: av.ID, AssetID: f.a1.ID}
	mustCreate(&f.artifactOnAsset1)

	f.repo = repositories.NewLabelRepository(db)
	f.service = services.NewLabelService(f.repo)
	f.controller = controllers.NewLabelController(f.service, f.repo)

	ptr := func(id uuid.UUID) *uuid.UUID { return &id }
	add := func(name string, org models.Org, project *models.Project, asset *models.Asset) {
		l := models.Label{Label: name, BackgroundColor: "#ff0000", OrganizationID: ptr(org.ID)}
		if project != nil {
			l.ProjectID = ptr(project.ID)
		}
		if asset != nil {
			l.AssetID = ptr(asset.ID)
		}
		require.NoError(t, f.repo.Create(context.Background(), nil, &l))
		f.labels[name] = l
	}
	add("org-a", f.orgA, nil, nil)
	add("p1", f.orgA, &f.p1, nil)
	add("p2", f.orgA, &f.p2, nil)
	add("a1", f.orgA, &f.p1, &f.a1)
	add("a2", f.orgA, &f.p1, &f.a2)
	add("a3", f.orgA, &f.p2, &f.a3)
	add("org-b", f.orgB, nil, nil)
	add("pb", f.orgB, &f.pB, nil)
	add("ab", f.orgB, &f.pB, &f.aB)
	return f
}

func labelNames(labels []dtos.Label) []string {
	names := make([]string, 0, len(labels))
	for _, l := range labels {
		names = append(names, l.Label)
	}
	return names
}

func TestLabelIntegration(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()
	ctx := context.Background()

	t.Run("List returns the labels of the own level and every level above, never of other orgs", func(t *testing.T) {
		f := newLabelFixture(t, db)

		org, err := f.service.ListOnOrgLevel(ctx, nil, f.orgA.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a"}, labelNames(org))

		project1, err := f.service.ListOnProjectLevel(ctx, nil, f.orgA.ID, f.p1.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p1"}, labelNames(project1), "sibling project p2 must not leak")

		project2, err := f.service.ListOnProjectLevel(ctx, nil, f.orgA.ID, f.p2.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p2"}, labelNames(project2))

		asset1, err := f.service.ListOnAssetLevel(ctx, nil, f.orgA.ID, f.p1.ID, f.a1.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p1", "a1"}, labelNames(asset1), "sibling asset a2 must not leak")

		asset2, err := f.service.ListOnAssetLevel(ctx, nil, f.orgA.ID, f.p1.ID, f.a2.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p1", "a2"}, labelNames(asset2))

		asset3, err := f.service.ListOnAssetLevel(ctx, nil, f.orgA.ID, f.p2.ID, f.a3.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p2", "a3"}, labelNames(asset3), "labels of project p1 must not leak")

		// the other tenant only sees its own labels
		orgB, err := f.service.ListOnAssetLevel(ctx, nil, f.orgB.ID, f.pB.ID, f.aB.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-b", "pb", "ab"}, labelNames(orgB))
	})

	t.Run("List does not return labels when asking with a project or asset of another org", func(t *testing.T) {
		f := newLabelFixture(t, db)

		// org B asking for the ids of org A: only org B's org-level label may show up
		project, err := f.service.ListOnProjectLevel(ctx, nil, f.orgB.ID, f.p1.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-b"}, labelNames(project))

		asset, err := f.service.ListOnAssetLevel(ctx, nil, f.orgB.ID, f.p1.ID, f.a1.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-b"}, labelNames(asset))

		// an asset which does not belong to the project does not match the asset level labels
		asset, err = f.service.ListOnAssetLevel(ctx, nil, f.orgA.ID, f.p2.ID, f.a1.ID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"org-a", "p2"}, labelNames(asset))
	})

	t.Run("List includes the computed text color and scope ids", func(t *testing.T) {
		f := newLabelFixture(t, db)

		labels, err := f.service.ListOnAssetLevel(ctx, nil, f.orgA.ID, f.p1.ID, f.a1.ID)
		require.NoError(t, err)
		for _, l := range labels {
			assert.NotEmpty(t, l.TextColor, l.Label)
			require.NotNil(t, l.OrganizationID, l.Label)
			assert.Equal(t, f.orgA.ID, *l.OrganizationID)
		}
	})

	t.Run("repository create, read, save and delete", func(t *testing.T) {
		f := newLabelFixture(t, db)

		label := models.Label{Label: "crud", BackgroundColor: "#00ff00", OrganizationID: &f.orgA.ID}
		require.NoError(t, f.repo.Create(ctx, nil, &label))
		assert.NotEqual(t, uuid.Nil, label.ID, "id must be generated")

		read, err := f.repo.Read(ctx, nil, label.ID)
		require.NoError(t, err)
		assert.Equal(t, "crud", read.Label)
		assert.Equal(t, "#00ff00", read.BackgroundColor)
		assert.True(t, read.IsDefinedAt(f.orgA.ID, nil, nil))

		read.Label = "crud-renamed"
		require.NoError(t, f.repo.Save(ctx, nil, &read))
		read, err = f.repo.Read(ctx, nil, label.ID)
		require.NoError(t, err)
		assert.Equal(t, "crud-renamed", read.Label)

		require.NoError(t, f.repo.Delete(ctx, nil, label.ID))
		_, err = f.repo.Read(ctx, nil, label.ID)
		assert.True(t, shared.IsNotFound(err))
	})

	t.Run("deleting a label removes its attachments", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		require.NoError(t, f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, nil, nil, &label.ID))
		assert.Equal(t, 1, attachmentCount(t, db, label.ID))

		require.NoError(t, f.repo.Delete(ctx, nil, label.ID))
		assert.Equal(t, 0, attachmentCount(t, db, label.ID))
	})

	t.Run("attach follows the label hierarchy", func(t *testing.T) {
		f := newLabelFixture(t, db)
		art := &f.artifactOnAsset1.ID

		type target struct {
			name     string
			project  *models.Project
			asset    *models.Asset
			artifact *uuid.UUID
		}
		onProject1 := target{"project p1", &f.p1, nil, nil}
		onAsset1 := target{"asset a1", &f.p1, &f.a1, nil}
		onAsset2 := target{"asset a2", &f.p1, &f.a2, nil}
		onArtifact := target{"artifact of a1", &f.p1, &f.a1, art}
		onProject2 := target{"project p2", &f.p2, nil, nil}

		cases := []struct {
			label   string
			target  target
			allowed bool
		}{
			// org level labels are usable everywhere in the org
			{"org-a", onProject1, true},
			{"org-a", onAsset1, true},
			{"org-a", onArtifact, true},
			// project level labels are usable below the project only
			{"p1", onProject1, true},
			{"p1", onAsset2, true},
			{"p1", onArtifact, true},
			{"p1", onProject2, false},
			{"p2", onProject1, false},
			{"p2", onAsset1, false},
			// asset level labels are usable on the asset and its artifacts only
			{"a1", onAsset1, true},
			{"a1", onArtifact, true},
			{"a1", onAsset2, false},
			{"a1", onProject1, false},
			{"a2", onArtifact, false},
			// labels of another org are never usable
			{"org-b", onProject1, false},
			{"pb", onAsset1, false},
			{"ab", onArtifact, false},
		}
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s on %s", c.label, c.target.name), func(t *testing.T) {
				var assetID *uuid.UUID
				if c.target.asset != nil {
					assetID = &c.target.asset.ID
				}
				label := f.labels[c.label]
				before := attachmentCount(t, db, label.ID)

				err := f.service.AttachLabel(ctx, db, f.orgA.ID, &c.target.project.ID, assetID, c.target.artifact, &label.ID)
				if c.allowed {
					require.NoError(t, err)
					assert.Equal(t, before+1, attachmentCount(t, db, label.ID))
				} else {
					assert.ErrorIs(t, err, shared.ErrLabelNotInScope)
					assert.Equal(t, before, attachmentCount(t, db, label.ID), "nothing may be attached")
				}
			})
		}
	})

	t.Run("attach with an unknown label is not found", func(t *testing.T) {
		f := newLabelFixture(t, db)
		unknown := uuid.New()

		err := f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, nil, nil, &unknown)
		assert.True(t, shared.IsNotFound(err))
	})

	t.Run("attach validates its input", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		assert.Error(t, f.service.AttachLabel(ctx, nil, f.orgA.ID, &f.p1.ID, nil, nil, &label.ID), "missing tx")
		assert.Error(t, f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, nil, nil, nil), "missing label")
		assert.Error(t, f.service.AttachLabel(ctx, db, f.orgA.ID, nil, nil, nil, &label.ID), "missing project")
	})

	t.Run("attached labels show up on the target", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["p1"]
		require.NoError(t, f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, &f.a1.ID, &f.artifactOnAsset1.ID, &label.ID))

		var artifact models.Artifact
		require.NoError(t, db.Preload("Labels").First(&artifact, "id = ?", f.artifactOnAsset1.ID).Error)
		require.Len(t, artifact.Labels, 1)
		assert.Equal(t, label.ID, artifact.Labels[0].ID)
	})

	t.Run("attaching the same label twice does not fail", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		require.NoError(t, f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, nil, nil, &label.ID))
		require.NoError(t, f.service.AttachLabel(ctx, db, f.orgA.ID, &f.p1.ID, nil, nil, &label.ID))
		assert.Equal(t, 1, attachmentCount(t, db, label.ID), "attachment must be idempotent")
	})
}

func attachmentCount(t *testing.T, db shared.DB, labelID uuid.UUID) int {
	t.Helper()
	var n int
	require.NoError(t, db.Raw("SELECT count(*) FROM projects_assets_artifacts_labels WHERE label_id = ?", labelID).Scan(&n).Error)
	return n
}

func TestLabelControllerIntegration(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	// level selects the url the request is made on
	type level int
	const (
		orgLevel level = iota
		projectLevel
		assetLevel
	)

	newCtx := func(f *labelFixture, method string, lvl level, labelID string, body string) (echo.Context, *httptest.ResponseRecorder) {
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		shared.SetOrg(c, f.orgA)
		if lvl >= projectLevel {
			shared.SetProject(c, f.p1)
		}
		if lvl >= assetLevel {
			shared.SetAsset(c, f.a1)
		}
		if labelID != "" {
			c.SetParamNames("labelID")
			c.SetParamValues(labelID)
		}
		return c, rec
	}
	statusOf := func(err error, rec *httptest.ResponseRecorder) int {
		if err != nil {
			var he *echo.HTTPError
			if assert.ErrorAs(t, err, &he) {
				return he.Code
			}
		}
		return rec.Code
	}

	t.Run("create sets the scope from the level of the request, not from the body", func(t *testing.T) {
		f := newLabelFixture(t, db)

		// the body tries to place the label into org B
		body := fmt.Sprintf(`{"label":"new","background_color":"#123456","organization_id":%q,"project_id":%q}`, f.orgB.ID, f.pB.ID)

		for _, tc := range []struct {
			lvl     level
			project *uuid.UUID
			asset   *uuid.UUID
		}{
			{orgLevel, nil, nil},
			{projectLevel, &f.p1.ID, nil},
			{assetLevel, &f.p1.ID, &f.a1.ID},
		} {
			c, rec := newCtx(f, http.MethodPost, tc.lvl, "", body)
			require.Equal(t, http.StatusOK, statusOf(f.controller.Create(c), rec))

			var created models.Label
			require.NoError(t, db.Where("label = ? AND organization_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ?",
				"new", f.orgA.ID, tc.project, tc.asset).First(&created).Error, "level %d", tc.lvl)
		}
	})

	t.Run("create and update reject invalid bodies", func(t *testing.T) {
		f := newLabelFixture(t, db)
		target := f.labels["org-a"]

		for name, body := range map[string]string{
			"missing label":      `{"background_color":"#123456"}`,
			"missing color":      `{"label":"x"}`,
			"color without hash": `{"label":"x","background_color":"123456"}`,
			"short color":        `{"label":"x","background_color":"#123"}`,
			"not a color":        `{"label":"x","background_color":"red"}`,
			"label too long":     fmt.Sprintf(`{"label":%q,"background_color":"#123456"}`, strings.Repeat("a", 257)),
		} {
			c, rec := newCtx(f, http.MethodPost, orgLevel, "", body)
			assert.Equal(t, http.StatusBadRequest, statusOf(f.controller.Create(c), rec), "create: "+name)

			c, rec = newCtx(f, http.MethodPut, orgLevel, target.ID.String(), body)
			assert.Equal(t, http.StatusBadRequest, statusOf(f.controller.Update(c), rec), "update: "+name)
		}
	})

	t.Run("update changes the label on its own level", func(t *testing.T) {
		f := newLabelFixture(t, db)

		for name, lvl := range map[string]level{"org-a": orgLevel, "p1": projectLevel, "a1": assetLevel} {
			label := f.labels[name]
			c, rec := newCtx(f, http.MethodPut, lvl, label.ID.String(), `{"label":"renamed","background_color":"#abcdef"}`)
			require.Equal(t, http.StatusOK, statusOf(f.controller.Update(c), rec), name)

			read, err := f.repo.Read(context.Background(), nil, label.ID)
			require.NoError(t, err)
			assert.Equal(t, "renamed", read.Label, name)
			assert.Equal(t, "#abcdef", read.BackgroundColor, name)
			assert.Equal(t, label.OrganizationID, read.OrganizationID, "scope must stay")
			assert.Equal(t, label.ProjectID, read.ProjectID, "scope must stay")
			assert.Equal(t, label.AssetID, read.AssetID, "scope must stay")
		}
	})

	t.Run("update uses the id of the url and ignores the id and scope of the body", func(t *testing.T) {
		f := newLabelFixture(t, db)
		target, other := f.labels["org-a"], f.labels["org-b"]

		body := fmt.Sprintf(`{"id":%q,"label":"hijack","background_color":"#123456","organization_id":%q}`, other.ID, f.orgB.ID)
		c, rec := newCtx(f, http.MethodPut, orgLevel, target.ID.String(), body)
		require.Equal(t, http.StatusOK, statusOf(f.controller.Update(c), rec))

		read, err := f.repo.Read(context.Background(), nil, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "hijack", read.Label)
		assert.Equal(t, f.orgA.ID, *read.OrganizationID)

		untouched, err := f.repo.Read(context.Background(), nil, other.ID)
		require.NoError(t, err)
		assert.Equal(t, "org-b", untouched.Label)
	})

	t.Run("update and delete reject labels of other levels and other orgs", func(t *testing.T) {
		f := newLabelFixture(t, db)

		cases := []struct {
			name  string
			label string
			lvl   level
		}{
			{"org label from project level", "org-a", projectLevel},
			{"org label from asset level", "org-a", assetLevel},
			{"project label from org level", "p1", orgLevel},
			{"project label from asset level", "p1", assetLevel},
			{"asset label from project level", "a1", projectLevel},
			{"asset label from org level", "a1", orgLevel},
			{"sibling project label", "p2", projectLevel},
			{"sibling asset label", "a2", assetLevel},
			{"label of another org on org level", "org-b", orgLevel},
			{"label of another org on project level", "pb", projectLevel},
			{"label of another org on asset level", "ab", assetLevel},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				label := f.labels[tc.label]

				c, rec := newCtx(f, http.MethodPut, tc.lvl, label.ID.String(), `{"label":"changed"}`)
				assert.Equal(t, http.StatusForbidden, statusOf(f.controller.Update(c), rec), "update")

				c, rec = newCtx(f, http.MethodDelete, tc.lvl, label.ID.String(), "")
				assert.Equal(t, http.StatusForbidden, statusOf(f.controller.Delete(c), rec), "delete")

				read, err := f.repo.Read(context.Background(), nil, label.ID)
				require.NoError(t, err, "label must still exist")
				assert.Equal(t, tc.label, read.Label, "label must be unchanged")
			})
		}
	})

	t.Run("delete removes the label on its own level", func(t *testing.T) {
		f := newLabelFixture(t, db)

		for name, lvl := range map[string]level{"org-a": orgLevel, "p1": projectLevel, "a1": assetLevel} {
			label := f.labels[name]
			c, rec := newCtx(f, http.MethodDelete, lvl, label.ID.String(), "")
			require.Equal(t, http.StatusOK, statusOf(f.controller.Delete(c), rec), name)

			_, err := f.repo.Read(context.Background(), nil, label.ID)
			assert.True(t, shared.IsNotFound(err), name)
		}
	})

	t.Run("update and delete with unknown or invalid ids", func(t *testing.T) {
		f := newLabelFixture(t, db)

		c, rec := newCtx(f, http.MethodPut, orgLevel, uuid.NewString(), `{"label":"x"}`)
		assert.Equal(t, http.StatusNotFound, statusOf(f.controller.Update(c), rec))
		c, rec = newCtx(f, http.MethodDelete, orgLevel, uuid.NewString(), "")
		assert.Equal(t, http.StatusNotFound, statusOf(f.controller.Delete(c), rec))

		c, rec = newCtx(f, http.MethodPut, orgLevel, "not-a-uuid", `{"label":"x"}`)
		assert.Equal(t, http.StatusBadRequest, statusOf(f.controller.Update(c), rec))
		c, rec = newCtx(f, http.MethodDelete, orgLevel, "not-a-uuid", "")
		assert.Equal(t, http.StatusBadRequest, statusOf(f.controller.Delete(c), rec))
	})

	t.Run("list endpoints return the labels of the level and above", func(t *testing.T) {
		f := newLabelFixture(t, db)

		read := func(handler func(echo.Context) error, lvl level) []string {
			c, rec := newCtx(f, http.MethodGet, lvl, "", "")
			require.Equal(t, http.StatusOK, statusOf(handler(c), rec))
			var labels []dtos.Label
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &labels))
			return labelNames(labels)
		}
		assert.ElementsMatch(t, []string{"org-a"}, read(f.controller.ListOnOrgLevel, orgLevel))
		assert.ElementsMatch(t, []string{"org-a", "p1"}, read(f.controller.ListOnProjectLevel, projectLevel))
		assert.ElementsMatch(t, []string{"org-a", "p1", "a1"}, read(f.controller.ListOnAssetLevel, assetLevel))
	})
}
