// Copyright (C) 2025 l3montree GmbH
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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// collectProductAndRelationshipIDs returns the set of base product ids and the set of
// relationship (combined) product ids in a CSAF product tree.
func collectProductAndRelationshipIDs(tree csaf.ProductTree) (products map[string]struct{}, relationships map[string]struct{}) {
	products = map[string]struct{}{}
	relationships = map[string]struct{}{}
	if tree.FullProductNames != nil {
		for _, product := range *tree.FullProductNames {
			products[string(*product.ProductID)] = struct{}{}
		}
	}
	if tree.RelationShips != nil {
		for _, relationship := range *tree.RelationShips {
			relationships[string(*relationship.FullProductName.ProductID)] = struct{}{}
		}
	}
	return products, relationships
}

func TestGenerateProductTree(t *testing.T) {
	_, _, artifact1, vulns := setUpVulns()
	artifact1Purl := normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)

	// expectedBaseAndLeaves derives, from a set of vulns, the base products (every path
	// component + each artifact) and the leaf product id of each vuln's path chain.
	expectedBaseAndLeaves := func(vs []models.DependencyVuln) (base map[string]struct{}, leaves map[string]struct{}) {
		base = map[string]struct{}{}
		leaves = map[string]struct{}{}
		for _, v := range vs {
			path := vulnPath(v)
			for _, c := range path {
				base[c] = struct{}{}
			}
			for _, artifact := range v.Artifacts {
				artifactPurl := normalize.Purlify(artifact.ArtifactName, artifact.AssetVersionName)
				base[artifactPurl] = struct{}{}
				leaves[leafProductID(artifactPurl, path)] = struct{}{}
			}
		}
		return base, leaves
	}

	t.Run("each dependency path is encoded as a relationship chain with a distinct leaf product", func(t *testing.T) {
		tree, err := generateProductTree(context.Background(), vulns)
		assert.NoError(t, err)

		expectedBase, expectedLeaves := expectedBaseAndLeaves(vulns)
		products, relationships := collectProductAndRelationshipIDs(tree)

		// every path component and the artifact should be a base product
		assert.Len(t, products, len(expectedBase))
		for id := range expectedBase {
			assert.Contains(t, products, id)
		}
		// every vuln path leaf product must be reachable as a relationship product
		for leaf := range expectedLeaves {
			assert.Contains(t, relationships, leaf)
		}
		// the artifact itself is a base product, never a relationship leaf
		assert.Contains(t, products, artifact1Purl)
	})

	t.Run("expand the product tree with an additional artifact containing a new vuln", func(t *testing.T) {
		artifact2 := artifact1
		artifact2.ArtifactName = "pkg:oci/scanner"

		newVuln := vulns[0]
		newVuln.Artifacts = []models.Artifact{artifact2}
		newVuln.ComponentPurl = "pkg:golang/github.com/sigstore/rekor@v1.3.10"

		all := append(append([]models.DependencyVuln{}, vulns...), newVuln)
		tree, err := generateProductTree(context.Background(), all)
		assert.NoError(t, err)

		expectedBase, expectedLeaves := expectedBaseAndLeaves(all)
		products, relationships := collectProductAndRelationshipIDs(tree)

		assert.Len(t, products, len(expectedBase))
		for id := range expectedBase {
			assert.Contains(t, products, id)
		}
		for leaf := range expectedLeaves {
			assert.Contains(t, relationships, leaf)
		}
		// both artifacts present as base products
		assert.Contains(t, products, artifact1Purl)
		assert.Contains(t, products, normalize.Purlify(artifact2.ArtifactName, artifact2.AssetVersionName))
	})
}

func TestCalculateVulnStateInformation(t *testing.T) {
	_, _, artifact1, vulns := setUpVulns()
	artifactPurl := normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)
	eventTime, err := time.Parse(time.RFC3339, "2028-02-11T11:11:11+00:00")
	if err != nil {
		panic(err)
	}

	t.Run("a single unhandled path is classified as under investigation", func(t *testing.T) {
		testVuln := vulns[0]
		leaf := leafProductID(artifactPurl, vulnPath(testVuln))

		productStatus, flags, distributions, remediations := calculateVulnStateInformation(context.Background(), []models.DependencyVuln{testVuln})
		affected, notAffected, fixed, underInvestigation := productStatusToSlices(*productStatus)

		assert.Empty(t, affected)
		assert.Empty(t, notAffected)
		assert.Empty(t, fixed)
		assert.Equal(t, []string{leaf}, underInvestigation)

		assert.Len(t, distributions, 1)
		assert.Equal(t, leaf, distributions[0].productID)
		assert.Equal(t, 1, distributions[0].TotalAmountOfPaths)
		assert.Equal(t, 1, distributions[0].AmountUnhandled)

		assert.Len(t, remediations, 0)
		assert.Len(t, flags, 0, "since the vulnerability is not handled as falsePositive we expect no flags")
	})

	t.Run("each path of the same component is classified independently (per-path granularity)", func(t *testing.T) {
		comp := "pkg:rpm/redhat/openssh-debugsource@v1.0.1"
		base := vulns[len(vulns)-1]
		base.ComponentPurl = comp

		makeVuln := func(path []string, state dtos.VulnState, ev *models.VulnEvent) models.DependencyVuln {
			v := base
			v.VulnerabilityPath = path
			v.State = state
			v.Events = append([]models.VulnEvent{}, base.Events...)
			if ev != nil {
				v.Events = append(v.Events, *ev)
			}
			return v
		}

		vUnhandled := makeVuln([]string{comp}, dtos.VulnStateOpen, nil)
		vFixed := makeVuln([]string{"pkg:generic/a@1.0.0", comp}, dtos.VulnStateFixed,
			&models.VulnEvent{CreatedAt: eventTime, Type: dtos.EventTypeFixed})
		vAccepted := makeVuln([]string{"pkg:generic/b@1.0.0", comp}, dtos.VulnStateAccepted,
			&models.VulnEvent{CreatedAt: eventTime, Justification: new("This is accepted"), Type: dtos.EventTypeAccepted})
		vFalsePositive := makeVuln([]string{"pkg:generic/c@1.0.0", comp}, dtos.VulnStateFalsePositive,
			&models.VulnEvent{CreatedAt: eventTime, Justification: new("This is a false positive"), MechanicalJustification: dtos.VulnerableCodeNotInExecutePath, Type: dtos.EventTypeFalsePositive})

		testVulns := []models.DependencyVuln{vUnhandled, vFixed, vAccepted, vFalsePositive}

		leafUnhandled := leafProductID(artifactPurl, vulnPath(vUnhandled))
		leafFixed := leafProductID(artifactPurl, vulnPath(vFixed))
		leafAccepted := leafProductID(artifactPurl, vulnPath(vAccepted))
		leafFP := leafProductID(artifactPurl, vulnPath(vFalsePositive))

		productStatus, flags, distributions, remediations := calculateVulnStateInformation(context.Background(), testVulns)
		affected, notAffected, fixed, underInvestigation := productStatusToSlices(*productStatus)

		// one product per path, each classified individually
		assert.Equal(t, []string{leafAccepted}, affected)
		assert.Equal(t, []string{leafFP}, notAffected)
		assert.Equal(t, []string{leafFixed}, fixed)
		assert.Equal(t, []string{leafUnhandled}, underInvestigation)

		// 4 distinct products, each with exactly one path
		assert.Len(t, distributions, 4)
		for _, d := range distributions {
			assert.Equal(t, 1, d.TotalAmountOfPaths)
		}

		// the accepted path yields a single no_fix_planned remediation
		assert.Len(t, remediations, 1)
		assert.Equal(t, csaf.CSAFRemediationCategoryNoFixPlanned, *remediations[0].Category)
		assert.Equal(t, csaf.ProductID(leafAccepted), *(*remediations[0].ProductIds)[0])
		assert.Contains(t, *remediations[0].Details, "accepted. Justification: This is accepted")

		// the false-positive path yields a single flag
		assert.Len(t, flags, 1)
		assert.Equal(t, dtos.VulnerableCodeNotInExecutePath, *flags[0].MechanicalJustification)
		assert.Len(t, flags[0].ProductIDs, 1)
		assert.Equal(t, csaf.ProductID(leafFP), *flags[0].ProductIDs[0])
		assert.Equal(t, eventTime, *flags[0].Date)
	})
}

func TestGetMostRecentJustifications(t *testing.T) {
	_, _, _, vulns := setUpVulns()
	eventTimeT1, err := time.Parse(time.RFC3339, "2026-02-10T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	eventTimeT2, err := time.Parse(time.RFC3339, "2026-02-11T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	eventTimeT3, err := time.Parse(time.RFC3339, "2026-02-12T11:11:11+00:00")
	if err != nil {
		panic(err)
	}

	t.Run("should return all nil if no justifications can be found", func(t *testing.T) {
		justification, mechanicalJustification, timeStamp := getMostRecentJustifications(vulns)
		assert.Nil(t, justification, timeStamp, mechanicalJustification)
	})
	t.Run("should return the latest justification if multiple are present", func(t *testing.T) {
		vulns[0].State = dtos.VulnStateFalsePositive
		vulns[0].Events = append(vulns[0].Events, models.VulnEvent{CreatedAt: eventTimeT1, Type: dtos.EventTypeFalsePositive, MechanicalJustification: dtos.VulnerableCodeNotInExecutePath, Justification: new("this information is outdated")})

		vulns[1].State = dtos.VulnStateFalsePositive
		vulns[1].Events = append(vulns[1].Events, models.VulnEvent{CreatedAt: eventTimeT2, Type: dtos.EventTypeFalsePositive, MechanicalJustification: dtos.ComponentNotPresent, Justification: new("this information is up to date")})

		// latest event has no justifications
		vulns[2].State = dtos.VulnStateFixed
		vulns[2].Events = append(vulns[2].Events, models.VulnEvent{CreatedAt: eventTimeT3, Type: dtos.EventTypeFixed})

		justification, mechanicalJustification, timestamp := getMostRecentJustifications(vulns)
		assert.Equal(t, "this information is up to date", *justification, "use the most recently provided justification")
		assert.Equal(t, *mechanicalJustification, dtos.ComponentNotPresent, "also take the latest mechanical justification at t2")
		assert.Equal(t, eventTimeT2, *timestamp, "timestamps should also match the one from the events")
	})
}

func TestGenerateTrackingObject(t *testing.T) {
	asset, _, artifact1, vulns := setUpVulns()
	eventTimeFalsePositives, err := time.Parse(time.RFC3339, "2026-02-11T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	eventTimeFixed, err := time.Parse(time.RFC3339, "2026-02-12T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	t.Run("build history with different vulns in different artifacts at different times", func(t *testing.T) {
		testVulnsArtifact1 := vulns              // end state 3 vulns (comp1: 2 paths (unhandled,unhandled), comp2: 1 path (fixed))
		testVulnsArtifact2 := testVulnsArtifact1 // end state 4 vulns (comp1: 2 paths (unhandled, falsePositive), comp2: 2 paths (falsePositive, falsePositive))

		vuln2Depth1 := vulns[len(vulns)-1]
		vuln2Depth1.VulnerabilityPath = []string{"comp1"}
		testVulnsArtifact2 = append(testVulnsArtifact2, vuln2Depth1)

		artifact2 := artifact1
		artifact2.ArtifactName = "pkg:oci/scanner"

		artifact2.DependencyVuln = testVulnsArtifact2
		for i := range testVulnsArtifact2 {
			testVulnsArtifact2[i].Artifacts = []models.Artifact{artifact2}
		}

		// mark 3 vulns as false positives (2/2 for the purl2 in artifact2 and 1/2 for purl1 in artifact2)
		falsePositiveVulns := []*models.DependencyVuln{&testVulnsArtifact2[3], &testVulnsArtifact2[2], &testVulnsArtifact2[1]}
		for _, vulnPtr := range falsePositiveVulns {
			vulnPtr.SetState(dtos.VulnStateFalsePositive)
			vulnPtr.Events = append(vulnPtr.Events, models.VulnEvent{CreatedAt: eventTimeFalsePositives, Justification: new("This is a false positive"), Type: dtos.EventTypeFalsePositive})
		}

		// mark last vuln from artifact 1 as fixed (since its a single path the whole vuln is therefore fixed)
		testVulnsArtifact1[len(testVulnsArtifact1)-1].State = dtos.VulnStateFixed
		testVulnsArtifact1[len(testVulnsArtifact1)-1].Events = append(testVulnsArtifact1[len(testVulnsArtifact1)-1].Events, models.VulnEvent{CreatedAt: eventTimeFixed, Type: dtos.EventTypeFixed})

		// calculate all vuln ID so we can sort by it
		for i := range testVulnsArtifact1 {
			testVulnsArtifact1[i].ID = testVulnsArtifact1[i].CalculateHash()
		}
		for i := range testVulnsArtifact2 {
			testVulnsArtifact2[i].ID = testVulnsArtifact2[i].CalculateHash()
		}

		tracking, err := generateTrackingObject(context.Background(), append(testVulnsArtifact1, testVulnsArtifact2...), GenerateDocumentTitle(asset.Name, testVulnsArtifact1[0].CVEID))
		assert.NoError(t, err)

		// the current release date should be the timestamp of the latest event
		currentRelease, err := time.Parse(time.RFC3339, *tracking.CurrentReleaseDate)
		assert.NoError(t, err)
		assert.True(t, eventTimeFixed.Equal(currentRelease))

		// 7 vulns each has a detected event (grouped to 2) + 3 false positive events (grouped to 2) + 1 fix event  = we expect 5 entries
		assert.Len(t, tracking.RevisionHistory, 5)
		// the version number should match the number of entries
		assert.Equal(t, strconv.Itoa(len(tracking.RevisionHistory)), string(*tracking.Version))

		// all detected Events should happen the earliest
		detectedEntries := tracking.RevisionHistory[:2]
		detectionTime := vulns[0].Events[0].CreatedAt
		for i, entry := range detectedEntries {
			date, err := time.Parse(time.RFC3339, *entry.Date)
			assert.NoError(t, err)
			assert.True(t, detectionTime.Equal(date))

			assert.Equal(t, strconv.Itoa(i+1), string(*entry.Number))
			assert.True(t, strings.Contains(*entry.Summary, "Detected"))
		}

		// then we should find all the false positives events
		falsePositiveEntries := tracking.RevisionHistory[2 : len(tracking.RevisionHistory)-1]
		for i, entry := range falsePositiveEntries {
			date, err := time.Parse(time.RFC3339, *entry.Date)
			assert.NoError(t, err)
			assert.True(t, eventTimeFalsePositives.Equal(date))

			assert.Equal(t, strconv.Itoa(i+1+len(detectedEntries)), string(*entry.Number))
			assert.True(t, strings.Contains(*entry.Summary, "as false positive"))
		}

		// lastly check for the fixed event as the last entry
		entry := tracking.RevisionHistory[len(tracking.RevisionHistory)-1]
		date, err := time.Parse(time.RFC3339, *entry.Date)
		assert.NoError(t, err)
		assert.True(t, eventTimeFixed.Equal(date))

		assert.Equal(t, strconv.Itoa(len(detectedEntries)+len(falsePositiveEntries)+1), string(*entry.Number))
		assert.True(t, strings.Contains(*entry.Summary, "Fixed"))

		// lastly check if we have correct amount of components and artifact in our revisions
		amountPurlKotlin := 0
		amountPurlDebug := 0

		amountArtifact1 := 0
		amountArtifact2 := 0

		for _, entry := range tracking.RevisionHistory {
			if strings.Contains(*entry.Summary, "pkg:github.com/jetbrains/kotlin@v872") {
				amountPurlKotlin++
			}
			if strings.Contains(*entry.Summary, "pkg:rpm/redhat/openssh-debugsource@v1.0.1") {
				amountPurlDebug++
			}
			if strings.Contains(*entry.Summary, normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)) {
				amountArtifact1++
			}
			if strings.Contains(*entry.Summary, normalize.Purlify(artifact2.ArtifactName, artifact2.AssetVersionName)) {
				amountArtifact2++
			}
		}

		assert.Equal(t, len(tracking.RevisionHistory), amountPurlKotlin+amountPurlDebug)
		// 3 detected events 1 fixed event
		assert.Equal(t, 3, amountArtifact1)
		// 4 detected events 3 falsePositives
		assert.Equal(t, 4, amountArtifact2)
		assert.Equal(t, 2, amountPurlKotlin)
		assert.Equal(t, 3, amountPurlDebug)

	})
}

// return all productIDs as strings in their respective slice (affected, notAffected, fixed, underInvestigation)
func productStatusToSlices(status csaf.ProductStatus) ([]string, []string, []string, []string) {
	affected := []string{}
	notAffected := []string{}
	fixed := []string{}
	underInvestigation := []string{}

	if status.KnownAffected != nil {
		for _, product := range *status.KnownAffected {
			affected = append(affected, string(*product))
		}
	}

	if status.KnownNotAffected != nil {
		for _, product := range *status.KnownNotAffected {
			notAffected = append(notAffected, string(*product))
		}
	}

	if status.Fixed != nil {
		for _, product := range *status.Fixed {
			fixed = append(fixed, string(*product))
		}
	}

	if status.UnderInvestigation != nil {
		for _, product := range *status.UnderInvestigation {
			underInvestigation = append(underInvestigation, string(*product))
		}
	}

	return affected, notAffected, fixed, underInvestigation
}

func setUpVulns() (models.Asset, models.AssetVersion, models.Artifact, []models.DependencyVuln) {
	time1, err := time.Parse(time.RFC3339, "2026-01-22T11:32:35+00:00")
	if err != nil {
		panic(err)
	}
	time2, err := time.Parse(time.RFC3339, "2026-01-25T11:32:35+00:00")
	if err != nil {
		panic(err)
	}

	id, err := uuid.Parse("191adab1-354f-47b5-9cea-aa6c960254cf")
	if err != nil {
		panic(err)
	}
	asset := models.Asset{Model: models.Model{ID: id, CreatedAt: time1}, Name: "CSAF Test Asset", Slug: "csaf-test"}
	assetVersion := models.AssetVersion{Name: "main", AssetID: asset.ID, Type: "branch", CreatedAt: time1, DefaultBranch: true, Slug: "main"}
	artifact := models.Artifact{ArtifactName: "pkg:devguard/testorg/testgroup/csaf-test", AssetVersionName: assetVersion.Name, AssetID: asset.ID, CreatedAt: time1}

	cve1 := models.CVE{CVE: "GO-2026-4309", Description: "Test Description", CVSS: 7.50, EPSS: new(0.00753)}

	affectedComponent1 := models.AffectedComponent{Ecosystem: "GIT", PurlWithoutVersion: "pkg:github.com/jetbrains/kotlin", Version: new("v872")}
	affectedComponent2 := models.AffectedComponent{Ecosystem: "GIT", PurlWithoutVersion: "pkg:github.com/jetbrains/kotlin", Version: new("build-0.7.536")}
	affectedComponent3 := models.AffectedComponent{Ecosystem: "rpm", PurlWithoutVersion: "pkg:rpm/redhat/openssh-debugsource", Version: new("v1.0.1")}

	cve1.AffectedComponents = append(cve1.AffectedComponents, affectedComponent1, affectedComponent2, affectedComponent3)

	vuln1Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:github.com/jetbrains/kotlin@v872", VulnerabilityPath: []string{}, CVEID: cve1.CVE, CVE: &cve1}
	vuln1Depth1 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:github.com/jetbrains/kotlin@v872", VulnerabilityPath: []string{"dep1"}, CVEID: cve1.CVE, CVE: &cve1}
	vuln2Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:rpm/redhat/openssh-debugsource@v1.0.1", VulnerabilityPath: []string{}, CVEID: cve1.CVE, CVE: &cve1}

	vuln1Depth0.Artifacts = append(vuln1Depth0.Artifacts, artifact)
	vuln1Depth1.Artifacts = append(vuln1Depth1.Artifacts, artifact)
	vuln2Depth0.Artifacts = append(vuln2Depth0.Artifacts, artifact)

	vuln10Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, DependencyVulnID: new(vuln1Depth0.CalculateHash()), CreatedAt: time2}
	vuln11Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, DependencyVulnID: new(vuln1Depth1.CalculateHash()), CreatedAt: time2}
	vuln20Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, DependencyVulnID: new(vuln2Depth0.CalculateHash()), CreatedAt: time2}

	vuln1Depth0.Events = append(vuln1Depth0.Events, vuln10Event1)
	vuln1Depth1.Events = append(vuln1Depth1.Events, vuln11Event1)
	vuln2Depth0.Events = append(vuln2Depth0.Events, vuln20Event1)

	artifact.DependencyVuln = append(artifact.DependencyVuln, vuln1Depth0, vuln1Depth1, vuln2Depth0)
	assetVersion.Artifacts = append(assetVersion.Artifacts, artifact)
	asset.AssetVersions = append(asset.AssetVersions, assetVersion)

	return asset, assetVersion, artifact, []models.DependencyVuln{vuln1Depth0, vuln1Depth1, vuln2Depth0}
}

func TestEmptySliceThenNil(t *testing.T) {
	t.Run("nil input should return nil", func(t *testing.T) {
		assert.Nil(t, emptySliceThenNil(nil))
	})
	t.Run("empty slice should return nil", func(t *testing.T) {
		empty := csaf.Products{}
		assert.Nil(t, emptySliceThenNil(&empty))
	})
	t.Run("non-empty slice should be returned as-is", func(t *testing.T) {
		id := csaf.ProductID("pkg:npm/debug@3.0.0")
		products := csaf.Products{&id}
		result := emptySliceThenNil(&products)
		assert.NotNil(t, result)
		assert.Len(t, *result, 1)
		assert.Equal(t, &id, (*result)[0])
	})
}

func TestGenerateDocumentTitle(t *testing.T) {
	t.Run("should handle realistic asset name and CVE", func(t *testing.T) {
		title := GenerateDocumentTitle("CSAF Test Asset", "GO-2026-4309")
		assert.NotNil(t, title)
		assert.Equal(t, "Security advisory for vulnerability GO-2026-4309 in asset CSAF Test Asset", *title)
	})
}

func TestGenerateSummaryForEvent(t *testing.T) {
	t.Run("single detected path in single artifact", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeDetected, 1, "pkg:npm/debug@3.0.0", []string{"pkg:oci/myapp@v1.0.0"})
		assert.Equal(t, "Detected 1 path in package pkg:npm/debug@3.0.0 (artifact: pkg:oci/myapp@v1.0.0)", result)
	})
	t.Run("multiple detected paths in single artifact", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeDetected, 3, "pkg:npm/debug@3.0.0", []string{"pkg:oci/myapp@v1.0.0"})
		assert.Equal(t, "Detected 3 paths in package pkg:npm/debug@3.0.0 (artifact: pkg:oci/myapp@v1.0.0)", result)
	})
	t.Run("single path in multiple artifacts", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeFixed, 1, "pkg:npm/debug@3.0.0", []string{"pkg:oci/app-a@v1.0.0", "pkg:oci/app-b@v2.0.0"})
		assert.Contains(t, result, "Fixed 1 path")
		assert.Contains(t, result, "artifacts:")
	})
	t.Run("multiple paths in multiple artifacts", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeAccepted, 5, "pkg:golang/github.com/lib/pq@v1.10.0", []string{"pkg:oci/api@v1.0.0", "pkg:oci/worker@v1.0.0"})
		assert.Contains(t, result, "Accepted 5 paths")
		assert.Contains(t, result, "artifacts:")
	})
	t.Run("false positive event type", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeFalsePositive, 2, "pkg:npm/lodash@4.17.20", []string{"pkg:oci/frontend@v3.0.0"})
		assert.Equal(t, "Marked 2 paths as false positive in package pkg:npm/lodash@4.17.20 (artifact: pkg:oci/frontend@v3.0.0)", result)
	})
	t.Run("reopened event type", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.EventTypeReopened, 1, "pkg:npm/debug@3.0.0", []string{"pkg:oci/myapp@v1.0.0"})
		assert.Equal(t, "Reopened 1 path in package pkg:npm/debug@3.0.0 (artifact: pkg:oci/myapp@v1.0.0)", result)
	})
	t.Run("unknown event type returns empty string", func(t *testing.T) {
		result := generateSummaryForEvent(dtos.VulnEventType("unknown"), 1, "pkg:npm/debug@3.0.0", []string{"pkg:oci/myapp@v1.0.0"})
		assert.Equal(t, "", result)
	})
}

// helper to unwrap packageurl.FromString in test data setup
func must(p packageurl.PackageURL, _ error) packageurl.PackageURL {
	return p
}

func TestGetOldestVulnPerUniqueCVE(t *testing.T) {
	asset, _, _, vulns := setUpVulns()
	t.Run("multiple vulns per CVE with different created_at timestamps should return slice with only the oldest vuln per CVE", func(t *testing.T) {
		allVulns := vulns
		// this is the vuln we should get as leader for this CVE
		allVulns[0].CreatedAt = allVulns[0].CreatedAt.Add(-2 * time.Hour)
		differentCVEVuln := vulns[0]
		differentCVEVuln.CVEID = "CVE-TEST-12345"
		allVulns = append(allVulns, differentCVEVuln)

		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		dependencyVulnRepository.On("GetAllVulnsByAssetID", mock.Anything, mock.Anything, mock.Anything).Return(allVulns, nil)

		csafService := csafService{
			dependencyVulnService: &DependencyVulnService{
				dependencyVulnRepository: dependencyVulnRepository,
			},
		}

		filteredVulns, err := csafService.GetOldestVulnPerUniqueCVE(context.Background(), asset.ID)

		assert.NoError(t, err)
		assert.Len(t, filteredVulns, 2, "3 vulns with 2 different CVEs should be deduplicated to 2 vulns with different CVEs")

		vulnAmountPerCVE := make(map[string]int, len(filteredVulns))
		for _, vuln := range filteredVulns {
			vulnAmountPerCVE[vuln.CVEID]++
			switch vuln.CVEID {
			case "CVE-TEST-12345":
				assert.True(t, differentCVEVuln.CreatedAt.Equal(vuln.CreatedAt), "only 1 vuln for the new CVE should return its timestamp")
			case "GO-2026-4309":
				assert.True(t, allVulns[0].CreatedAt.Equal(vuln.CreatedAt), "2 vulns for this CVE, should return the older one")
			}
		}
		assert.Len(t, vulnAmountPerCVE, 2, "2 different CVEs")
		assert.Equal(t, 1, vulnAmountPerCVE["CVE-TEST-12345"], "both CVEs should only appear once")
		assert.Equal(t, 1, vulnAmountPerCVE["GO-2026-4309"], "both CVEs should only appear once")
	})
}

func TestIsCVE(t *testing.T) {
	t.Run("invalid CVE should return false", func(t *testing.T) {
		assert.False(t, utils.IsCVE("Vulnerability 3492"))
	})
	t.Run("not official CVE should return false", func(t *testing.T) {
		assert.False(t, utils.IsCVE("GO-2025-4135"))
	})
	t.Run("valid CVE should return true", func(t *testing.T) {
		assert.True(t, utils.IsCVE("CVE-2025-4135"))
	})
}
