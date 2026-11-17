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
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard-cli/hashmigrations"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runHashMigrationV12(t *testing.T, f *TestFixture) {
	t.Helper()
	require.NoError(t, f.DB.Exec(`INSERT INTO config (key, val) VALUES ('hash_migration_version', '11')
		ON CONFLICT (key) DO UPDATE SET val = '11'`).Error)
	require.NoError(t, hashmigrations.RunHashMigrationsIfNeeded(f.Pool, nil, nil, nil, nil))
}

// TestComplianceScopeMigration seeds compliance data the way it was stored before catalogs and components were
// scoped: global controls identified by "<framework>:<control_id>", postures referencing them and global components.
func TestComplianceScopeMigration(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// legacy postures reference "<framework>:<control_id>", which the foreign key of the new schema rejects
		require.NoError(t, f.DB.Exec(`ALTER TABLE compliance_postures DROP CONSTRAINT fk_compliance_postures_control_hash`).Error)

		insertControl := func(framework, controlID, title, prose string, parent *string) {
			require.NoError(t, f.DB.Exec(`INSERT INTO compliance_controls (framework, control_id, title, class, description, importance, security_level, additional, parent_control_id)
				VALUES (?, ?, ?, '', ?, 'MUSS', 'normal-SdT', '{"guidance": "legacy", "tags": {"value": "a"}}', ?)`,
				framework, controlID, title, prose, parent).Error)
		}
		insertControl("Grundschutz++", "GOV.1", "Governance", "Define responsibilities.", nil)
		gov1 := "GOV.1"
		insertControl("Grundschutz++", "GOV.1.1", "Sub Governance", "Document responsibilities.", &gov1)
		// the same content in another framework becomes one control
		insertControl("Lieferkettensicherheit", "GOV.1", "Governance", "Define responsibilities.", nil)
		insertControl("Lieferkettensicherheit", "OPS.1", "Operations", "Encrypt data at rest.", nil)
		// a framework without postures is not activated anywhere
		insertControl("SCF", "SCF.1", "Unused", "Nobody uses this.", nil)

		insertPosture := func(frameworkControlID string, state dtos.VulnState, projectID *uuid.UUID, onAssetVersion bool) uuid.UUID {
			id := uuid.New()
			var assetID, assetVersionID *uuid.UUID
			var assetVersionName *string
			if onAssetVersion {
				assetID, assetVersionID, assetVersionName = &asset.ID, &assetVersion.ID, &assetVersion.Name
			}
			require.NoError(t, f.DB.Exec(`INSERT INTO compliance_postures (id, state, org_id, project_id, asset_id, asset_version_id, asset_version_name, control_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				id, state, org.ID, projectID, assetID, assetVersionID, assetVersionName, frameworkControlID).Error)
			return id
		}
		orgGov1 := insertPosture("Grundschutz++:GOV.1", dtos.VulnStateImplemented, nil, false)
		assetGov11 := insertPosture("Grundschutz++:GOV.1.1", dtos.VulnStateImplemented, &project.ID, true)
		projectOps1 := insertPosture("Lieferkettensicherheit:OPS.1", dtos.VulnStateNotApplicable, &project.ID, false)
		assetGov1 := insertPosture("Lieferkettensicherheit:GOV.1", dtos.VulnStateImplemented, &project.ID, true)

		event := models.NewImplementedEvent(assetGov11, dtos.VulnTypeCompliancePosture, "user", "done", nil)
		require.NoError(t, f.DB.Create(&event).Error)

		usedComponent := uuid.New()
		unusedComponent := uuid.New()
		for _, id := range []uuid.UUID{usedComponent, unusedComponent} {
			require.NoError(t, f.DB.Exec(`INSERT INTO compliance_components (id, uuid, title, description) VALUES (?, ?, 'Branch Protection', 'Protected branches')`, id, id).Error)
			require.NoError(t, f.DB.Exec(`INSERT INTO compliance_component_implements_controls (framework_control_id, compliance_component_id, description) VALUES ('Grundschutz++:GOV.1.1', ?, 'Enforce reviews')`, id).Error)
		}
		statementID := uuid.New()
		require.NoError(t, f.DB.Exec(`INSERT INTO compliance_component_implements_control_statements (id, compliance_posture_id, compliance_component_id, framework_control_id, implementation_status, description)
			VALUES (?, ?, ?, 'Grundschutz++:GOV.1.1', 'implemented', 'enabled')`, statementID, assetGov11, usedComponent).Error)

		require.NoError(t, f.DB.Exec(`ALTER TABLE ONLY compliance_postures ADD CONSTRAINT fk_compliance_postures_control_hash
			FOREIGN KEY (control_hash) REFERENCES compliance_controls(control_hash) ON DELETE CASCADE NOT VALID`).Error)

		runHashMigrationV12(t, f)

		t.Run("controls are identified by their hash and unused controls are deleted", func(t *testing.T) {
			var controls []models.FrameworkControl
			require.NoError(t, f.DB.Find(&controls).Error)
			assert.ElementsMatch(t, []string{"GOV.1", "GOV.1.1", "OPS.1"}, controlIDsOf(controls))
			for _, c := range controls {
				assert.Equal(t, c.CalculateHash(), c.ControlHash, "the hash of %s is the hash of its content", c.ControlID)
			}
		})

		t.Run("the used frameworks are activated where they were used", func(t *testing.T) {
			var scopeFrameworks []models.ScopeFramework
			require.NoError(t, f.DB.Where("org_id = ?", org.ID).Find(&scopeFrameworks).Error)
			type scope struct {
				framework string
				project   bool
			}
			got := make([]scope, 0, len(scopeFrameworks))
			for _, sf := range scopeFrameworks {
				assert.Nil(t, sf.AssetID)
				got = append(got, scope{framework: sf.Framework, project: sf.ProjectID != nil})
			}
			assert.ElementsMatch(t, []scope{
				{framework: "Grundschutz++", project: false},
				{framework: "Grundschutz++", project: true},
				{framework: "Lieferkettensicherheit", project: true},
			}, got)
		})

		t.Run("the postures keep their state on the new hash", func(t *testing.T) {
			paged, err := f.App.CompliancePostureService.GetForAllControlsPaged(ctx, nil, &assetVersion.ID, &asset.ID, &project.ID, org.ID, shared.PageInfo{Page: 1, PageSize: 100}, "", nil, nil)
			require.NoError(t, err)
			byID := make(map[string]dtos.CompliancePostureWithControl)
			for _, p := range paged.Data {
				byID[p.ControlID] = p
			}
			require.Len(t, byID, 3)

			assert.Equal(t, []string{"Grundschutz++", "Lieferkettensicherheit"}, byID["GOV.1"].Frameworks)
			assert.Equal(t, dtos.VulnStateImplemented, byID["GOV.1"].State)
			assert.Equal(t, dtos.VulnStateImplemented, byID["GOV.1.1"].State)
			assert.Equal(t, dtos.VulnStateNotApplicable, byID["OPS.1"].State, "the posture of the project is inherited")

			var count int64
			require.NoError(t, f.DB.Model(&models.CompliancePosture{}).Where("id IN ?", []uuid.UUID{orgGov1, assetGov11, projectOps1, assetGov1}).Count(&count).Error)
			assert.Zero(t, count, "the legacy postures are deleted")
		})

		t.Run("events and statements are moved to the new posture", func(t *testing.T) {
			var gov11 models.FrameworkControl
			require.NoError(t, f.DB.Where("control_id = ?", "GOV.1.1").First(&gov11).Error)
			newID := models.CalculateCompliancePostureHash(gov11.ControlHash, org.ID, &project.ID, &asset.ID, &assetVersion.Name)

			posture, err := f.App.CompliancePostureService.GetForControl(ctx, nil, gov11.ControlHash, &assetVersion.ID, &asset.ID, &project.ID, org.ID)
			require.NoError(t, err)
			assert.Equal(t, newID, posture.ID)
			require.Len(t, posture.Events, 1)
			assert.Equal(t, event.ID, posture.Events[0].ID)
			require.Len(t, posture.ByComponents, 1)
			assert.Equal(t, statementID, posture.ByComponents[0].ID)
		})

		t.Run("the used components are scoped to the project and the global ones are deleted", func(t *testing.T) {
			var global int64
			require.NoError(t, f.DB.Model(&models.ComplianceComponent{}).Where("org_id IS NULL").Count(&global).Error)
			assert.Zero(t, global)

			components, err := f.App.ComplianceComponentRepository.ListAll(ctx, nil, org.ID, &project.ID, &asset.ID, nil)
			require.NoError(t, err)
			require.Len(t, components, 1)
			component := components[0]
			assert.Equal(t, usedComponent, component.UUID)
			assert.NotEqual(t, usedComponent, component.ID)
			require.NotNil(t, component.ComponentDefinition)
			assert.Equal(t, "Grundschutz++ Compliance Mapping", *component.ComponentDefinition)
			assert.Equal(t, &project.ID, component.ProjectID)
			require.Len(t, component.ImplementedControls, 1)
			assert.Equal(t, "Grundschutz++:GOV.1.1", component.ImplementedControls[0].FrameworkControlID)

			var statement models.ComplianceComponentImplementsControlStatement
			require.NoError(t, f.DB.Where("id = ?", statementID).First(&statement).Error)
			assert.Equal(t, component.ID, statement.ComplianceComponentID)
		})

		t.Run("the foreign key of the postures is validated", func(t *testing.T) {
			var validated bool
			require.NoError(t, f.DB.Raw(`SELECT convalidated FROM pg_constraint WHERE conname = 'fk_compliance_postures_control_hash'`).Scan(&validated).Error)
			assert.True(t, validated)
		})

		t.Run("running the migration again changes nothing", func(t *testing.T) {
			var before, after int64
			require.NoError(t, f.DB.Model(&models.CompliancePosture{}).Count(&before).Error)
			runHashMigrationV12(t, f)
			require.NoError(t, f.DB.Model(&models.CompliancePosture{}).Count(&after).Error)
			assert.Equal(t, before, after)
		})
	})
}

func controlIDsOf(controls []models.FrameworkControl) []string {
	ids := make([]string, len(controls))
	for i, c := range controls {
		ids[i] = c.ControlID
	}
	return ids
}
