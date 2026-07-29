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
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVEXRuleMarkedVulnMustNotStayOpen reproduces the reported inconsistency: a
// dependency vuln on the default branch carries the falsePositive event of a VEX rule
// (created_by_vex_rule = true, vex_rule_id set, no originalAssetVersionName) while its
// state is still "open" - the details page shows a "VEX Rule marked" event on an open
// vuln, and no reopened/detected event explains how it got back to open.
//
// The reproduction is the interleaving that produces that DB state: a scan of the branch
// is in flight while the rule is created. A scan reads the vulns it is going to persist
// at the beginning (scanService.handleScanResult -> ListUnfixedByAssetAndAssetVersion,
// returned as newState) and writes them back at the very end
// (HandleScanResult -> RecalculateRawRiskAssessment -> SaveBatchBestEffort). That write
// is a full-row upsert, so it also writes the `state` column of the copy it read minutes
// earlier - silently reverting every assessment that happened in between, without
// recording an event. devguard's own pipelines scan several artifacts of the same branch
// (arm64/amd64) per run, so this window is wide open in practice.
//
// Once the vuln is back to open while its last event is the rule's falsePositive event,
// it also stays that way: VEXRuleService.applyRulesToExisting skips vulns whose last
// event already matches the event the rule would create (isVexEventAlreadyApplied), so
// neither a later scan nor the daemon's ApplyVEXRules stage repairs the state.
func TestVEXRuleMarkedVulnMustNotStayOpen(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		app := echo.New()
		setupCtx := func(ctx shared.Context) {
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, NewUserSession(t, "user-abc"))
		}

		const mainArtifact = "art-main-arm64"
		const featureBranch = "fix/e2e-pipeline"

		scan := func(artifactName, ref string, sbom io.Reader) {
			t.Helper()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbom)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", ref)
			req.Header.Set("X-Origin", "test-origin")
			recorder := httptest.NewRecorder()
			ctx := app.NewContext(req, recorder)
			setupCtx(ctx)
			require.NoError(t, f.App.ScanController.ScanDependencyVulnFromProject(ctx))
			require.Equal(t, 200, recorder.Code, recorder.Body.String())
		}

		loadVuln := func(branch string) models.DependencyVuln {
			t.Helper()
			var vulns []models.DependencyVuln
			require.NoError(t, f.DB.Preload("Events").Where(
				"asset_id = ? AND asset_version_name = ? AND cve_id = ?",
				asset.ID, branch, "CVE-2025-46569",
			).Find(&vulns).Error)
			require.Len(t, vulns, 1, "expected exactly one CVE-2025-46569 vuln on %s", branch)
			return vulns[0]
		}

		// the vuln is on the default branch first, then the feature branch is created and
		// inherits it - same CVE, same path incl. versions.
		scan(mainArtifact, "main", sbomWithVulnerability())
		scan("art-fix-arm64", featureBranch, sbomWithVulnerability())

		mainVuln := loadVuln("main")
		featureVuln := loadVuln(featureBranch)
		require.Equal(t, mainVuln.VulnerabilityPath, featureVuln.VulnerabilityPath)
		require.Equal(t, mainVuln.CalculateAssetVersionIndependentHash(), featureVuln.CalculateAssetVersionIndependentHash())
		require.Equal(t, dtos.VulnStateOpen, mainVuln.State)
		require.Equal(t, dtos.VulnStateOpen, featureVuln.State)

		// a scan of the default branch is in flight: it has read the vulns it will write
		// back when it finishes - exactly what handleScanResult returns as newState.
		inFlightScanState, err := f.App.DependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(
			context.Background(), nil, "main", asset.ID, new(mainArtifact))
		require.NoError(t, err)
		require.NotEmpty(t, inFlightScanState)

		// meanwhile the user creates a VEX rule from the feature branch's vuln details
		// page: this CVE is not exploitable through this direct dependency.
		celExpression := vexrules.ToCELExpression("CVE-2025-46569",
			vexrules.PathPattern(append([]string{"ROOT"}, featureVuln.VulnerabilityPath...)))
		ruleID := createVEXRuleViaAPI(t, f, app, setupCtx, celExpression)

		// the rule is scoped to the asset, so it closes the vuln on every branch
		require.Equal(t, dtos.VulnStateFalsePositive, loadVuln(featureBranch).State,
			"vuln on the branch the rule was created from must be marked as false positive")
		require.Equal(t, dtos.VulnStateFalsePositive, loadVuln("main").State,
			"identical vuln on the default branch must be marked as false positive too")

		// the in-flight scan finishes and persists the copies it read before the rule ran
		_, err = f.App.DependencyVulnService.RecalculateRawRiskAssessment(
			context.Background(), nil, "system", inFlightScanState, "", asset)
		require.NoError(t, err)

		mainVuln = loadVuln("main")

		// the rule's event is still there ...
		vexEvent, ok := findVexRuleEvent(mainVuln.Events, ruleID)
		require.True(t, ok, "expected the rule's falsePositive event on the default branch vuln")
		require.True(t, vexEvent.CreatedByVexRule)
		require.Nil(t, vexEvent.OriginalAssetVersionName, "the event was created on this branch, not copied")

		// ... so the vuln must not be open again: nothing may drop a vuln's assessed state
		// without an event explaining it.
		assert.Equal(t, dtos.VulnStateFalsePositive, mainVuln.State,
			"vuln carries the VEX rule's %s event (vex_rule_id=%s) but was silently reset to %s.%s",
			vexEvent.Type, ruleID, mainVuln.State, debugEvents(mainVuln))

		for _, ev := range mainVuln.Events {
			assert.NotEqual(t, dtos.EventTypeReopened, ev.Type,
				"no reopened event should exist - the state change was not audited at all")
		}

		// the other branch is unaffected, which is why this only ever shows up on the
		// branch that happened to be scanned while the rule was created.
		assert.Equal(t, dtos.VulnStateFalsePositive, loadVuln(featureBranch).State)
	})
}

// createVEXRuleViaAPI creates a manual VEX rule through the same endpoint the vuln
// details page uses and returns the created rule's ID.
func createVEXRuleViaAPI(t *testing.T, f *TestFixture, app *echo.Echo, setupCtx func(shared.Context), celExpression string) string {
	t.Helper()
	body, err := json.Marshal(dtos.CreateVEXRuleRequest{
		Title:                   "CVE-2025-46569 not exploitable",
		Justification:           "opa comes with the base image. We do not use this package.",
		MechanicalJustification: dtos.VulnerableCodeNotInExecutePath,
		CELExpression:           celExpression,
		EventType:               dtos.EventTypeFalsePositive,
	})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/vex-rules", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx := app.NewContext(req, recorder)
	setupCtx(ctx)
	require.NoError(t, f.App.VEXRuleController.Create(ctx))
	require.Equal(t, 201, recorder.Code, recorder.Body.String())

	var rule dtos.VEXRuleDTO
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &rule))
	require.NotEmpty(t, rule.ID)
	return rule.ID
}

// findVexRuleEvent returns the event that the given VEX rule created, if any.
func findVexRuleEvent(events []models.VulnEvent, ruleID string) (models.VulnEvent, bool) {
	for _, ev := range events {
		if ev.VexRuleID != nil && *ev.VexRuleID == ruleID {
			return ev, true
		}
	}
	return models.VulnEvent{}, false
}

// debugEvents renders a vuln's event history for failure messages.
func debugEvents(vuln models.DependencyVuln) string {
	var sb strings.Builder
	sb.WriteString("\nevents:")
	for _, ev := range vuln.GetEvents() {
		ruleID := ""
		if ev.VexRuleID != nil {
			ruleID = *ev.VexRuleID
		}
		origin := ""
		if ev.OriginalAssetVersionName != nil {
			origin = *ev.OriginalAssetVersionName
		}
		fmt.Fprintf(&sb, "\n  %s type=%-14s createdByVexRule=%-5t vexRuleID=%s originalAssetVersion=%q",
			ev.CreatedAt.Format("2006-01-02 15:04:05"), ev.Type, ev.CreatedByVexRule, ruleID, origin)
	}
	return sb.String()
}
