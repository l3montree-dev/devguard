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

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAggregatedCSAFRoundTrip verifies that an aggregated CSAF advisory covering multiple
// CVEs (as served by the artifact/release csaf.json endpoints) round-trips back into exact,
// per-path VEX rules - one rule per false-positive path, none for the open paths - and that
// each reconstructed rule still matches the exact same DependencyVuln it was generated from.
//
// The CSAF product tree is always rooted at the artifact, so PathPattern carries an artifact
// purl prefix that VulnerabilityPath itself never has (see vexrules.PathPattern.MatchesSuffixForArtifacts
// and models.DependencyVuln.ArtifactPurls) - without stripping that prefix during matching, a
// downloaded CSAF report re-uploaded to devguard would never match any of its own vulns.
func TestAggregatedCSAFRoundTrip(t *testing.T) {
	assetID := uuid.New()
	artifact := models.Artifact{ArtifactName: "pkg:oci/app", AssetVersionName: "main", AssetID: assetID}
	eventTime := time.Now()

	mk := func(cveID, comp string, path []string, state dtos.VulnState, falsePositive bool) models.DependencyVuln {
		cve := models.CVE{CVE: cveID, Description: "desc"}
		v := models.DependencyVuln{
			Vulnerability:     models.Vulnerability{AssetVersionName: "main", AssetID: assetID, State: state},
			CVEID:             cveID,
			CVE:               &cve,
			ComponentPurl:     comp,
			VulnerabilityPath: path,
			Artifacts:         []models.Artifact{artifact},
			Events:            []models.VulnEvent{{Type: dtos.EventTypeDetected, CreatedAt: eventTime}},
		}
		if falsePositive {
			j := "not reachable"
			v.Events = append(v.Events, models.VulnEvent{Type: dtos.EventTypeFalsePositive, CreatedAt: eventTime, Justification: &j})
		}
		return v
	}

	compA, compB := "pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"
	pathA1 := []string{"pkg:npm/dep-a1@1.0.0", compA} // false positive
	pathA2 := []string{"pkg:npm/dep-a2@1.0.0", compA} // open
	pathB1 := []string{"pkg:npm/dep-b1@1.0.0", compB} // false positive
	pathB2 := []string{"pkg:npm/dep-b2@1.0.0", compB} // open

	vulnA1 := mk("CVE-2024-0001", compA, pathA1, dtos.VulnStateFalsePositive, true)
	vulnB1 := mk("CVE-2024-0002", compB, pathB1, dtos.VulnStateFalsePositive, true)
	vulns := []models.DependencyVuln{
		vulnA1,
		mk("CVE-2024-0001", compA, pathA2, dtos.VulnStateOpen, false),
		vulnB1,
		mk("CVE-2024-0002", compB, pathB2, dtos.VulnStateOpen, false),
	}

	title := "Security advisory for release r1"
	advisory, err := csafService{}.GenerateCSAFReportForVulns(context.Background(), "org", &title, vulns)
	require.NoError(t, err)
	assert.Len(t, advisory.Vulnerabilities, 2, "one CSAF vulnerability object per CVE")

	rules, err := transformer.CSAFVEXToRules(&advisory, "aggregated")
	require.NoError(t, err)

	// exactly the two false-positive paths become rules, each with its exact (non-wildcard) path,
	// prefixed with the artifact product since CSAF's product tree is rooted at the artifact
	require.Len(t, rules, 2)
	for _, r := range rules {
		assert.Equal(t, dtos.EventTypeFalsePositive, r.EventType)
	}

	// The crucial roundtrip step: re-matching each rule's CEL expression against the exact
	// DependencyVuln it was generated from must succeed, even though the rule's path pattern
	// carries the artifact prefix that VulnerabilityPath itself never does.
	for cveID, vuln := range map[string]models.DependencyVuln{"CVE-2024-0001": vulnA1, "CVE-2024-0002": vulnB1} {
		var matched bool
		for _, r := range rules {
			matches, err := vexrules.EvalRules(context.Background(), []models.UpstreamVEXRule{r}, vuln)
			require.NoError(t, err)
			if matches[r.ID] {
				matched = true
			}
		}
		assert.True(t, matched, "reconstructed rule for %s must match the vuln it was generated from", cveID)
	}

	// And the open (non-false-positive) paths must NOT match any reconstructed rule -
	// otherwise re-uploading the CSAF report would incorrectly resolve an open vuln too.
	openA := mk("CVE-2024-0001", compA, pathA2, dtos.VulnStateOpen, false)
	for _, r := range rules {
		matches, err := vexrules.EvalRules(context.Background(), []models.UpstreamVEXRule{r}, openA)
		require.NoError(t, err)
		assert.False(t, matches[r.ID], "the open path must not match the false-positive path's rule")
	}
}

// TestCSAFRoundTripMultiplePathsToSharedComponent verifies that when the same vulnerable
// component is reachable through several distinct dependency chains - including chains that
// share an intermediate component (opa) but diverge above it (go-witness vs cosign) - each
// path is encoded as its own distinct product/relationship chain, round-trips back into its
// own exact VEX rule path without paths bleeding into each other, and each reconstructed rule
// still matches the exact DependencyVuln it came from once the artifact prefix is stripped.
//
// Graph under test:
//
//	ARTIFACT -> vuln
//	ARTIFACT -> opa -> vuln
//	ARTIFACT -> go-witness -> opa -> vuln
//	ARTIFACT -> cosign -> opa -> vuln
func TestCSAFRoundTripMultiplePathsToSharedComponent(t *testing.T) {
	assetID := uuid.New()
	artifact := models.Artifact{ArtifactName: "pkg:golang/github.com/l3montree-dev/devguard@main", AssetVersionName: "main", AssetID: assetID}
	eventTime := time.Now()

	cveID := "GHSA-fxhp-mv3v-67qp"
	vulnPurl := "pkg:golang/oras.land/oras-go/v2@v2.6.1"
	opaPurl := "pkg:golang/github.com/open-policy-agent/opa@v1.18.2"
	goWitnessPurl := "pkg:golang/github.com/in-toto/go-witness@v0.11.0"
	cosignPurl := "pkg:golang/github.com/sigstore/cosign/v2@v2.6.3"

	mk := func(path []string) models.DependencyVuln {
		cve := models.CVE{CVE: cveID, Description: "desc"}
		j := "not reachable"
		return models.DependencyVuln{
			Vulnerability:     models.Vulnerability{AssetVersionName: "main", AssetID: assetID, State: dtos.VulnStateFalsePositive},
			CVEID:             cveID,
			CVE:               &cve,
			ComponentPurl:     vulnPurl,
			VulnerabilityPath: path,
			Artifacts:         []models.Artifact{artifact},
			Events: []models.VulnEvent{
				{Type: dtos.EventTypeDetected, CreatedAt: eventTime},
				{Type: dtos.EventTypeFalsePositive, CreatedAt: eventTime, Justification: &j},
			},
		}
	}

	pathDirect := []string{vulnPurl}
	pathViaOPA := []string{opaPurl, vulnPurl}
	pathViaGoWitness := []string{goWitnessPurl, opaPurl, vulnPurl}
	pathViaCosign := []string{cosignPurl, opaPurl, vulnPurl}

	vulns := []models.DependencyVuln{
		mk(pathDirect),
		mk(pathViaOPA),
		mk(pathViaGoWitness),
		mk(pathViaCosign),
	}

	title := "Security advisory for pkg:golang/github.com/l3montree-dev/devguard@main"
	advisory, err := csafService{}.GenerateCSAFReportForVulns(context.Background(), "org", &title, vulns)
	require.NoError(t, err)
	require.Len(t, advisory.Vulnerabilities, 1, "one CSAF vulnerability object for the single CVE")

	rules, err := transformer.CSAFVEXToRules(&advisory, "test")
	require.NoError(t, err)

	// each of the 4 distinct paths must round-trip into its own exact-path rule, each prefixed
	// with the artifact product since CSAF's product tree is rooted at the artifact
	require.Len(t, rules, 4, "each distinct path must yield its own VEX rule")

	for _, r := range rules {
		assert.Equal(t, dtos.EventTypeFalsePositive, r.EventType)
	}

	// Each reconstructed rule must match back onto exactly the vuln whose path it encodes,
	// and none of the others - proving distinct paths through a shared component (opa)
	// don't bleed into each other once the artifact prefix is stripped for matching.
	for i, vuln := range vulns {
		matchCount := 0
		for _, r := range rules {
			matches, err := vexrules.EvalRules(context.Background(), []models.UpstreamVEXRule{r}, vuln)
			require.NoError(t, err)
			if matches[r.ID] {
				matchCount++
			}
		}
		assert.Equal(t, 1, matchCount, "vuln %d (path %v) must match exactly one reconstructed rule", i, vuln.VulnerabilityPath)
	}
}
