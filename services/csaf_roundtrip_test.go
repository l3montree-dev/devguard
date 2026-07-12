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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAggregatedCSAFRoundTrip verifies that an aggregated CSAF advisory covering multiple
// CVEs (as served by the artifact/release csaf.json endpoints) round-trips back into exact,
// per-path VEX rules - one rule per false-positive path, none for the open paths.
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

	vulns := []models.DependencyVuln{
		mk("CVE-2024-0001", compA, pathA1, dtos.VulnStateFalsePositive, true),
		mk("CVE-2024-0001", compA, pathA2, dtos.VulnStateOpen, false),
		mk("CVE-2024-0002", compB, pathB1, dtos.VulnStateFalsePositive, true),
		mk("CVE-2024-0002", compB, pathB2, dtos.VulnStateOpen, false),
	}

	title := "Security advisory for release r1"
	advisory, err := csafService{}.GenerateCSAFReportForVulns(context.Background(), "org", &title, vulns)
	require.NoError(t, err)
	assert.Len(t, advisory.Vulnerabilities, 2, "one CSAF vulnerability object per CVE")

	rules, err := transformer.CSAFVEXToRules(&advisory, assetID, "main", "aggregated")
	require.NoError(t, err)

	// exactly the two false-positive paths become rules, each with its exact (non-wildcard) path,
	// prefixed with the artifact product since CSAF's product tree is rooted at the artifact
	artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
	require.Len(t, rules, 2)
	byCVE := map[string]dtos.PathPattern{}
	for _, r := range rules {
		assert.Equal(t, dtos.EventTypeFalsePositive, r.EventType)
		byCVE[r.CVEID] = r.PathPattern
	}
	assert.Equal(t, append([]string{artifactPurl}, pathA1...), []string(byCVE["CVE-2024-0001"]))
	assert.Equal(t, append([]string{artifactPurl}, pathB1...), []string(byCVE["CVE-2024-0002"]))
}

// TestCSAFRoundTripMultiplePathsToSharedComponent verifies that when the same vulnerable
// component is reachable through several distinct dependency chains - including chains that
// share an intermediate component (opa) but diverge above it (go-witness vs cosign) - each
// path is encoded as its own distinct product/relationship chain and round-trips back into its
// own exact VEX rule path, without paths bleeding into each other.
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

	rules, err := transformer.CSAFVEXToRules(&advisory, assetID, "main", "test")
	require.NoError(t, err)

	// each of the 4 distinct paths must round-trip into its own exact-path rule, each prefixed
	// with the artifact product since CSAF's product tree is rooted at the artifact
	require.Len(t, rules, 4, "each distinct path must yield its own VEX rule")

	artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
	seen := map[string]dtos.PathPattern{}
	for _, r := range rules {
		assert.Equal(t, dtos.EventTypeFalsePositive, r.EventType)
		seen[strings.Join(r.PathPattern, ",")] = r.PathPattern
	}

	withArtifact := func(path []string) dtos.PathPattern {
		return dtos.PathPattern(append([]string{artifactPurl}, path...))
	}
	expected := []dtos.PathPattern{
		withArtifact(pathDirect),
		withArtifact(pathViaOPA),
		withArtifact(pathViaGoWitness),
		withArtifact(pathViaCosign),
	}
	for _, exp := range expected {
		got, ok := seen[strings.Join(exp, ",")]
		assert.True(t, ok, "expected path %v to be present among the round-tripped rules", []string(exp))
		assert.Equal(t, []string(exp), []string(got), "path elements and order must be preserved exactly")
	}
}
