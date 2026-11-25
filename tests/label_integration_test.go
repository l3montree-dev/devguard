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
	f.controller = controllers.NewLabelController(f.repo)

	ptr := func(id uuid.UUID) *uuid.UUID { return &id }
	add := func(name string, org models.Org, project *models.Project, asset *models.Asset) {
		l := models.Label{Label: name, BackgroundColor: "#ff0000", OrganizationID: org.ID}
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

// attachBody calls the attach endpoint of the controller on the given level and returns the http status.
// The level is derived from the nil-ness of project, asset and artifact. The organization is always org A.
func (f *labelFixture) attachBody(t *testing.T, project *models.Project, asset *models.Asset, artifact *models.Artifact, body string) int {
	t.Helper()
	status, _ := f.attachBodyResponse(t, project, asset, artifact, body)
	return status
}

// attachBodyResponse is attachBody, additionally returning the raw response body.
func (f *labelFixture) attachBodyResponse(t *testing.T, project *models.Project, asset *models.Asset, artifact *models.Artifact, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	shared.SetOrg(c, f.orgA)
	if project != nil {
		shared.SetProject(c, *project)
	}
	if asset != nil {
		shared.SetAsset(c, *asset)
	}
	if artifact != nil {
		shared.SetArtifact(c, *artifact)
	}

	if err := f.controller.AttachLabel(c); err != nil {
		var he *echo.HTTPError
		require.ErrorAs(t, err, &he)
		return he.Code, nil
	}
	return rec.Code, rec.Body.Bytes()
}

// attach attaches the labels with the given ids on the given level and returns the http status.
func (f *labelFixture) attach(t *testing.T, project *models.Project, asset *models.Asset, artifact *models.Artifact, ids ...uuid.UUID) int {
	t.Helper()
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		labels = append(labels, id.String())
	}
	body, err := json.Marshal(map[string][]string{"label": labels})
	require.NoError(t, err)
	return f.attachBody(t, project, asset, artifact, string(body))
}

// attachAndRead attaches the labels with the given ids on the given level and returns the http status
// together with the labels of the response body.
func (f *labelFixture) attachAndRead(t *testing.T, project *models.Project, asset *models.Asset, artifact *models.Artifact, ids ...uuid.UUID) (int, []models.Label) {
	t.Helper()
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		labels = append(labels, id.String())
	}
	body, err := json.Marshal(map[string][]string{"label": labels})
	require.NoError(t, err)

	status, raw := f.attachBodyResponse(t, project, asset, artifact, string(body))
	if status != http.StatusOK {
		return status, nil
	}
	var res []models.Label
	require.NoError(t, json.Unmarshal(raw, &res), "response must be a list of labels")
	return status, res
}

func labelNames(labels []models.Label) []string {
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

	list := func(t *testing.T, f *labelFixture, org models.Org, project *models.Project, asset *models.Asset) []string {
		t.Helper()
		var projectID, assetID *uuid.UUID
		if project != nil {
			projectID = &project.ID
		}
		if asset != nil {
			assetID = &asset.ID
		}
		labels, err := f.repo.ListThroughHierarchy(ctx, nil, &org.ID, projectID, assetID)
		require.NoError(t, err)
		names := make([]string, 0, len(labels))
		for _, l := range labels {
			names = append(names, l.Label)
		}
		return names
	}

	t.Run("List returns the labels of the own level and every level above, never of other orgs", func(t *testing.T) {
		f := newLabelFixture(t, db)

		assert.ElementsMatch(t, []string{"org-a"}, list(t, f, f.orgA, nil, nil))
		assert.ElementsMatch(t, []string{"org-a", "p1"}, list(t, f, f.orgA, &f.p1, nil), "sibling project p2 must not leak")
		assert.ElementsMatch(t, []string{"org-a", "p2"}, list(t, f, f.orgA, &f.p2, nil))
		assert.ElementsMatch(t, []string{"org-a", "p1", "a1"}, list(t, f, f.orgA, &f.p1, &f.a1), "sibling asset a2 must not leak")
		assert.ElementsMatch(t, []string{"org-a", "p1", "a2"}, list(t, f, f.orgA, &f.p1, &f.a2))
		assert.ElementsMatch(t, []string{"org-a", "p2", "a3"}, list(t, f, f.orgA, &f.p2, &f.a3), "labels of project p1 must not leak")

		// the other tenant only sees its own labels
		assert.ElementsMatch(t, []string{"org-b", "pb", "ab"}, list(t, f, f.orgB, &f.pB, &f.aB))
	})

	t.Run("List does not return labels when asking with a project or asset of another org", func(t *testing.T) {
		f := newLabelFixture(t, db)

		// org B asking for the ids of org A: only org B's org-level label may show up
		assert.ElementsMatch(t, []string{"org-b"}, list(t, f, f.orgB, &f.p1, nil))
		assert.ElementsMatch(t, []string{"org-b"}, list(t, f, f.orgB, &f.p1, &f.a1))

		// an asset which does not belong to the project does not match the asset level labels
		assert.ElementsMatch(t, []string{"org-a", "p2"}, list(t, f, f.orgA, &f.p2, &f.a1))
	})

	t.Run("repository create, read, save and delete", func(t *testing.T) {
		f := newLabelFixture(t, db)

		label := models.Label{Label: "crud", BackgroundColor: "#00ff00", OrganizationID: f.orgA.ID}
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

		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, nil, nil, label.ID))
		assert.Equal(t, 1, attachmentCount(t, db, label.ID))

		require.NoError(t, f.repo.Delete(ctx, nil, label.ID))
		assert.Equal(t, 0, attachmentCount(t, db, label.ID))
	})

	t.Run("attach follows the label hierarchy", func(t *testing.T) {
		f := newLabelFixture(t, db)
		type target struct {
			name     string
			project  *models.Project
			asset    *models.Asset
			artifact *models.Artifact
		}
		onProject1 := target{"project p1", &f.p1, nil, nil}
		onAsset1 := target{"asset a1", &f.p1, &f.a1, nil}
		onAsset2 := target{"asset a2", &f.p1, &f.a2, nil}
		onArtifact := target{"artifact of a1", &f.p1, &f.a1, &f.artifactOnAsset1}
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
				label := f.labels[c.label]
				before := attachmentCount(t, db, label.ID)

				status := f.attach(t, c.target.project, c.target.asset, c.target.artifact, label.ID)
				if c.allowed {
					require.Equal(t, http.StatusOK, status)
					assert.Equal(t, before+1, attachmentCount(t, db, label.ID))
				} else {
					assert.Equal(t, http.StatusBadRequest, status, "label must not be visible from the target")
					assert.Equal(t, before, attachmentCount(t, db, label.ID), "nothing may be attached")
				}
			})
		}
	})

	t.Run("attach with an unknown label is rejected", func(t *testing.T) {
		f := newLabelFixture(t, db)

		assert.Equal(t, http.StatusBadRequest, f.attach(t, &f.p1, nil, nil, uuid.New()))
	})

	t.Run("attach multiple labels at once", func(t *testing.T) {
		f := newLabelFixture(t, db)
		ids := []uuid.UUID{f.labels["org-a"].ID, f.labels["p1"].ID, f.labels["a1"].ID}

		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, &f.a1, &f.artifactOnAsset1, ids...))

		var artifact models.Artifact
		require.NoError(t, db.Preload("Labels").First(&artifact, "id = ?", f.artifactOnAsset1.ID).Error)
		attached := make([]uuid.UUID, 0, len(artifact.Labels))
		for _, l := range artifact.Labels {
			attached = append(attached, l.ID)
		}
		assert.ElementsMatch(t, ids, attached)
	})

	t.Run("attach returns the attached labels", func(t *testing.T) {
		f := newLabelFixture(t, db)
		requested := []uuid.UUID{f.labels["org-a"].ID, f.labels["p1"].ID, f.labels["a1"].ID}

		status, returned := f.attachAndRead(t, &f.p1, &f.a1, &f.artifactOnAsset1, requested...)
		require.Equal(t, http.StatusOK, status)

		// the order of the response is not guaranteed, so compare the ids and the content
		returnedIDs := make([]uuid.UUID, 0, len(returned))
		for _, l := range returned {
			returnedIDs = append(returnedIDs, l.ID)
			expected := f.labels[l.Label]
			assert.Equal(t, expected.ID, l.ID, l.Label)
			assert.Equal(t, expected.BackgroundColor, l.BackgroundColor, l.Label)
			assert.Equal(t, expected.OrganizationID, l.OrganizationID, l.Label)
			assert.Equal(t, expected.ProjectID, l.ProjectID, l.Label)
			assert.Equal(t, expected.AssetID, l.AssetID, l.Label)
		}
		assert.ElementsMatch(t, requested, returnedIDs, "exactly the requested labels must be returned")
	})

	t.Run("attach returns the labels again when they are already attached", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		status, _ := f.attachAndRead(t, &f.p1, nil, nil, label.ID)
		require.Equal(t, http.StatusOK, status)

		status, returned := f.attachAndRead(t, &f.p1, nil, nil, label.ID)
		require.Equal(t, http.StatusOK, status)
		require.Len(t, returned, 1)
		assert.Equal(t, label.ID, returned[0].ID)
	})

	t.Run("attach multiple labels on every level", func(t *testing.T) {
		f := newLabelFixture(t, db)

		// project level
		projectLabels := []uuid.UUID{f.labels["org-a"].ID, f.labels["p1"].ID}
		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, nil, nil, projectLabels...))
		for _, id := range projectLabels {
			assert.Equal(t, 1, attachmentCount(t, db, id))
		}

		// asset level
		assetLabels := []uuid.UUID{f.labels["org-a"].ID, f.labels["a1"].ID}
		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, &f.a1, nil, assetLabels...))
		assert.Equal(t, 2, attachmentCount(t, db, f.labels["org-a"].ID), "org-a is now attached to the project and the asset")
		assert.Equal(t, 1, attachmentCount(t, db, f.labels["a1"].ID))
	})

	t.Run("attaching multiple labels is all or nothing", func(t *testing.T) {
		f := newLabelFixture(t, db)
		valid := f.labels["org-a"]

		for name, invalid := range map[string]uuid.UUID{
			"unknown label":        uuid.New(),
			"label of another org": f.labels["org-b"].ID,
			"sibling project":      f.labels["p2"].ID,
			"sibling asset":        f.labels["a2"].ID,
		} {
			assert.Equal(t, http.StatusBadRequest, f.attach(t, &f.p1, &f.a1, nil, valid.ID, invalid), name)
			assert.Equal(t, 0, attachmentCount(t, db, valid.ID), "%s: the valid label must not be attached either", name)
		}
	})

	t.Run("attach rejects duplicate ids in the same request", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		assert.Equal(t, http.StatusBadRequest, f.attach(t, &f.p1, nil, nil, label.ID, label.ID))
		assert.Equal(t, 0, attachmentCount(t, db, label.ID), "nothing may be attached")
	})

	t.Run("attach validates its input", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		assert.Equal(t, http.StatusBadRequest, f.attachBody(t, &f.p1, nil, nil, `{}`), "missing labels")
		assert.Equal(t, http.StatusBadRequest, f.attachBody(t, &f.p1, nil, nil, `{"label":null}`), "null labels")
		assert.Equal(t, http.StatusBadRequest, f.attachBody(t, &f.p1, nil, nil, `{"label":[]}`), "empty labels")
		assert.Equal(t, http.StatusBadRequest, f.attachBody(t, &f.p1, nil, nil, `{"label":["not-a-uuid"]}`), "invalid uuid")
		assert.Equal(t, http.StatusBadRequest, f.attachBody(t, &f.p1, nil, nil, `not json`), "invalid body")
		assert.Equal(t, http.StatusBadRequest, f.attach(t, nil, nil, nil, label.ID), "missing project")
		assert.Equal(t, 0, attachmentCount(t, db, label.ID), "nothing may be attached")
	})

	t.Run("attached labels show up on the target", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["p1"]
		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, &f.a1, &f.artifactOnAsset1, label.ID))

		var artifact models.Artifact
		require.NoError(t, db.Preload("Labels").First(&artifact, "id = ?", f.artifactOnAsset1.ID).Error)
		require.Len(t, artifact.Labels, 1)
		assert.Equal(t, label.ID, artifact.Labels[0].ID)
	})

	t.Run("attaching the same label twice does not fail", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]

		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, nil, nil, label.ID))
		require.Equal(t, http.StatusOK, f.attach(t, &f.p1, nil, nil, label.ID))
		assert.Equal(t, 1, attachmentCount(t, db, label.ID), "attachment must be idempotent")
	})
}

func TestLabelRepositoryCreateLabelAttachmentBatch(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()
	ctx := context.Background()

	type attachmentRow struct {
		ProjectID  *uuid.UUID
		AssetID    *uuid.UUID
		ArtifactID *uuid.UUID
		LabelID    uuid.UUID
	}
	ptr := func(id uuid.UUID) *uuid.UUID { return &id }
	rowsOf := func(t *testing.T, labelIDs ...uuid.UUID) []attachmentRow {
		t.Helper()
		var rows []attachmentRow
		require.NoError(t, db.Raw("SELECT project_id, asset_id, artifact_id, label_id FROM projects_assets_artifacts_labels WHERE label_id IN ?", labelIDs).Scan(&rows).Error)
		return rows
	}

	t.Run("an empty batch is a no-op", func(t *testing.T) {
		f := newLabelFixture(t, db)

		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, nil, &f.p1.ID, nil, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{}, &f.p1.ID, nil, nil))
	})

	t.Run("the batch is stored on the most specific level that is given", func(t *testing.T) {
		f := newLabelFixture(t, db)
		onProject, onAsset, onArtifact := f.labels["org-a"], f.labels["p1"], f.labels["a1"]

		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{onProject.ID}, &f.p1.ID, nil, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{onAsset.ID}, &f.p1.ID, &f.a1.ID, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{onArtifact.ID}, &f.p1.ID, &f.a1.ID, &f.artifactOnAsset1.ID))

		// only the target of the most specific level is persisted, the other columns stay NULL
		assert.ElementsMatch(t, []attachmentRow{
			{ProjectID: ptr(f.p1.ID), LabelID: onProject.ID},
			{AssetID: ptr(f.a1.ID), LabelID: onAsset.ID},
			{ArtifactID: ptr(f.artifactOnAsset1.ID), LabelID: onArtifact.ID},
		}, rowsOf(t, onProject.ID, onAsset.ID, onArtifact.ID))
	})

	t.Run("many labels can be attached to the same target in one batch", func(t *testing.T) {
		f := newLabelFixture(t, db)
		ids := []uuid.UUID{f.labels["org-a"].ID, f.labels["p1"].ID, f.labels["a1"].ID}

		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, ids, &f.p1.ID, &f.a1.ID, &f.artifactOnAsset1.ID))

		rows := rowsOf(t, ids...)
		require.Len(t, rows, len(ids))
		attached := make([]uuid.UUID, 0, len(rows))
		for _, r := range rows {
			require.NotNil(t, r.ArtifactID)
			assert.Equal(t, f.artifactOnAsset1.ID, *r.ArtifactID)
			assert.Nil(t, r.ProjectID)
			assert.Nil(t, r.AssetID)
			attached = append(attached, r.LabelID)
		}
		assert.ElementsMatch(t, ids, attached)
	})

	t.Run("the same label can be attached to different targets", func(t *testing.T) {
		f := newLabelFixture(t, db)
		label := f.labels["org-a"]
		ids := []uuid.UUID{label.ID}

		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, ids, &f.p1.ID, nil, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, ids, &f.p1.ID, &f.a1.ID, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, ids, &f.p1.ID, &f.a2.ID, nil))
		assert.Equal(t, 3, attachmentCount(t, db, label.ID))
	})

	t.Run("existing attachments are skipped without failing the rest of the batch", func(t *testing.T) {
		f := newLabelFixture(t, db)
		existing, fresh := f.labels["org-a"], f.labels["p1"]

		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{existing.ID}, &f.p1.ID, nil, nil))
		require.NoError(t, f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{existing.ID, fresh.ID}, &f.p1.ID, nil, nil))

		assert.Equal(t, 1, attachmentCount(t, db, existing.ID), "no duplicate row")
		assert.Equal(t, 1, attachmentCount(t, db, fresh.ID), "new row next to the skipped one is still inserted")
	})

	t.Run("an unknown label id fails the whole batch", func(t *testing.T) {
		f := newLabelFixture(t, db)
		valid := f.labels["org-a"]

		err := f.repo.CreateLabelAttachmentBatch(ctx, nil, []uuid.UUID{valid.ID, uuid.New()}, &f.p1.ID, nil, nil)
		require.Error(t, err, "foreign key on label_id must reject the unknown label")
		assert.Equal(t, 0, attachmentCount(t, db, valid.ID), "the valid row must be rolled back with the invalid one")
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
		assert.Equal(t, f.orgA.ID, read.OrganizationID)

		untouched, err := f.repo.Read(context.Background(), nil, other.ID)
		require.NoError(t, err)
		assert.Equal(t, "org-b", untouched.Label)
	})

	t.Run("update and delete reject labels of other levels and other orgs", func(t *testing.T) {
		f := newLabelFixture(t, db)

		// labels visible from the level of the request, but defined on another level: forbidden.
		// labels not visible from the level of the request at all: not found.
		cases := []struct {
			name   string
			label  string
			lvl    level
			status int
		}{
			{"org label from project level", "org-a", projectLevel, http.StatusForbidden},
			{"org label from asset level", "org-a", assetLevel, http.StatusForbidden},
			{"project label from asset level", "p1", assetLevel, http.StatusForbidden},
			{"project label from org level", "p1", orgLevel, http.StatusNotFound},
			{"asset label from project level", "a1", projectLevel, http.StatusNotFound},
			{"asset label from org level", "a1", orgLevel, http.StatusNotFound},
			{"sibling project label", "p2", projectLevel, http.StatusNotFound},
			{"sibling asset label", "a2", assetLevel, http.StatusNotFound},
			{"label of another org on org level", "org-b", orgLevel, http.StatusNotFound},
			{"label of another org on project level", "pb", projectLevel, http.StatusNotFound},
			{"label of another org on asset level", "ab", assetLevel, http.StatusNotFound},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				label := f.labels[tc.label]

				c, rec := newCtx(f, http.MethodPut, tc.lvl, label.ID.String(), `{"label":"changed"}`)
				assert.Equal(t, tc.status, statusOf(f.controller.Update(c), rec), "update")

				c, rec = newCtx(f, http.MethodDelete, tc.lvl, label.ID.String(), "")
				assert.Equal(t, tc.status, statusOf(f.controller.Delete(c), rec), "delete")

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
			var labels []models.Label
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &labels))
			return labelNames(labels)
		}
		assert.ElementsMatch(t, []string{"org-a"}, read(f.controller.ListOnOrgLevel, orgLevel))
		assert.ElementsMatch(t, []string{"org-a", "p1"}, read(f.controller.ListOnProjectLevel, projectLevel))
		assert.ElementsMatch(t, []string{"org-a", "p1", "a1"}, read(f.controller.ListOnAssetLevel, assetLevel))
	})

	t.Run("list endpoints include the scope ids", func(t *testing.T) {
		f := newLabelFixture(t, db)

		c, rec := newCtx(f, http.MethodGet, assetLevel, "", "")
		require.Equal(t, http.StatusOK, statusOf(f.controller.ListOnAssetLevel(c), rec))
		var labels []models.Label
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &labels))
		require.NotEmpty(t, labels)
		for _, l := range labels {
			require.NotNil(t, l.OrganizationID, l.Label)
			assert.Equal(t, f.orgA.ID, l.OrganizationID)
		}
	})

	t.Run("create and update reject duplicates on every level", func(t *testing.T) {
		f := newLabelFixture(t, db)
		body := `{"label":"dup","background_color":"#123456"}`

		for _, lvl := range []level{orgLevel, projectLevel, assetLevel} {
			c, rec := newCtx(f, http.MethodPost, lvl, "", body)
			require.Equal(t, http.StatusOK, statusOf(f.controller.Create(c), rec), "first create")

			c, rec = newCtx(f, http.MethodPost, lvl, "", body)
			assert.Equal(t, http.StatusConflict, statusOf(f.controller.Create(c), rec), "duplicate create, level %d", lvl)
		}

		// renaming into an existing label of the same level is a conflict too
		c, rec := newCtx(f, http.MethodPut, orgLevel, f.labels["org-a"].ID.String(), body)
		assert.Equal(t, http.StatusConflict, statusOf(f.controller.Update(c), rec))

		// the same label on a different level is fine
		c, rec = newCtx(f, http.MethodPost, projectLevel, "", `{"label":"org-a","background_color":"#ff0000"}`)
		assert.Equal(t, http.StatusOK, statusOf(f.controller.Create(c), rec))
	})

}
