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
package statemachine

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestDiffScanResults(t *testing.T) {

	t.Run("should correctly identify a vulnerability which now gets found by another artifact", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		assetID := uuid.New()
		assetVersionName := "asset-version-1"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: "CVE-1234", Vulnerability: models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID}},
		}

		artifact := models.Artifact{ArtifactName: "artifact1", AssetVersionName: assetVersionName, AssetID: assetID}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: "CVE-1234", Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersionName, AssetID: assetID,
			}, Artifacts: []models.Artifact{artifact}},
		}

		diff := DiffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, diff.NewlyDiscovered)
		assert.Empty(t, diff.FixedEverywhere)
		assert.Empty(t, diff.RemovedFromArtifact)
		assert.Equal(t, 1, len(diff.Unchanged))
		assert.Equal(t, 1, len(diff.NewInArtifact))
	})

	t.Run("should correctly identify a vulnerability which now is fixed, since it was not found by the artifact anymore", func(t *testing.T) {

		assetID := uuid.New()

		artifact := models.Artifact{ArtifactName: "artifact1", AssetVersionName: "asset-version-1", AssetID: assetID}

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: "CVE-1234", Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		diff := DiffScanResults(artifact.ArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, diff.NewlyDiscovered)
		assert.Empty(t, diff.Unchanged)
		assert.Equal(t, 1, len(diff.FixedEverywhere))
		assert.Empty(t, diff.NewInArtifact)
		assert.Empty(t, diff.RemovedFromArtifact)
	})

	t.Run("should correctly identify a vulnerability which is not found in the current artifact anymore", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: "CVE-1234", Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		diff := DiffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, diff.NewlyDiscovered)
		assert.Empty(t, diff.FixedEverywhere)
		assert.Empty(t, diff.Unchanged)
		assert.Empty(t, diff.NewInArtifact)
		assert.Equal(t, 1, len(diff.RemovedFromArtifact))
	})

	t.Run("should identify new vulnerabilities", func(t *testing.T) {
		currentArtifactName := "new-artifact"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: "CVE-1234"},
			{CVEID: "CVE-5678"},
		}

		existingDependencyVulns := []models.DependencyVuln{}

		diff := DiffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Equal(t, 2, len(diff.NewlyDiscovered))
		assert.Empty(t, diff.FixedEverywhere)
		assert.Empty(t, diff.Unchanged)
		assert.Empty(t, diff.NewInArtifact)
		assert.Empty(t, diff.RemovedFromArtifact)
	})

	t.Run("BUG: should NOT incorrectly identify artifact removal when artifact ID contains colon and is substring of existing artifact", func(t *testing.T) {

		currentArtifactName := "container-scanning"

		artifact := models.Artifact{ArtifactName: "artifact1"}

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: "CVE-1234"},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: "CVE-1234", Vulnerability: models.Vulnerability{}, Artifacts: []models.Artifact{artifact}},
		}

		diff := DiffScanResults(currentArtifactName, foundVulnerabilities, existingDependencyVulns)

		assert.Equal(t, 1, len(diff.Unchanged))
		assert.Empty(t, diff.NewlyDiscovered, "Should be empty - this is a new detection by current artifact")
		assert.Empty(t, diff.FixedEverywhere, "Should be empty - no vulnerabilities are fixed")
		assert.Equal(t, 1, len(diff.NewInArtifact), "Should detect that current artifact found existing vulnerability for first time")
		assert.Empty(t, diff.RemovedFromArtifact, "BUG: Should be empty - current artifact was never detecting this vulnerability before!")
	})
}

func TestDiffVulnsBetweenBranches(t *testing.T) {

	t.Run("should copy events when vuln exists on other branch", func(t *testing.T) {
		assetID := uuid.New()

		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					ID:               "vuln-1",
					AssetVersionName: "feature-branch",
					AssetID:          assetID,
					Events:           []models.VulnEvent{},
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					ID:               "vuln-2",
					AssetVersionName: "main",
					AssetID:          assetID,
					Events: []models.VulnEvent{{Type: dtos.EventTypeDetected},
						{Type: dtos.EventTypeComment}},
				},
				Artifacts: []models.Artifact{{ArtifactName: "artifact1", AssetVersionName: "feature-branch", AssetID: assetID},
					{ArtifactName: "artifact2", AssetVersionName: "feature-branch", AssetID: assetID}},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		assert.Empty(t, diffResult.NewToAllBranches)
		assert.Len(t, diffResult.ExistingOnOtherBranches, 1)
		assert.Len(t, diffResult.ExistingOnOtherBranches[0].EventsToCopy, 2)
	})

	t.Run("should identify new vulnerabilities not on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: "CVE-2023-0002",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0003",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
				},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		newDetectedVulnsNotOnOtherBranch := diffResult.NewToAllBranches
		newDetectedButOnOtherBranchExisting := diffResult.ExistingOnOtherBranches

		assert.Len(t, newDetectedVulnsNotOnOtherBranch, 2)
		assert.Empty(t, newDetectedButOnOtherBranchExisting)
		assert.Equal(t, "CVE-2023-0001", newDetectedVulnsNotOnOtherBranch[0].CVEID)
		assert.Equal(t, "CVE-2023-0002", newDetectedVulnsNotOnOtherBranch[1].CVEID)
	})

	t.Run("should identify vulnerabilities that exist on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: dtos.EventTypeAccepted,
						},
					},
				},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		assert.Empty(t, diffResult.NewToAllBranches)
		assert.Len(t, diffResult.ExistingOnOtherBranches, 1)
		assert.Len(t, diffResult.ExistingOnOtherBranches[0].EventsToCopy, 1)
		assert.Equal(t, "CVE-2023-0001", diffResult.ExistingOnOtherBranches[0].CurrentBranchVuln.CVEID)
		assert.Equal(t, "main", *diffResult.ExistingOnOtherBranches[0].EventsToCopy[0].OriginalAssetVersionName)
	})

	t.Run("should handle multiple vulnerabilities with same CVE on other branch", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: dtos.EventTypeComment,
						},
					},
				},
			},
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "develop",
					Events: []models.VulnEvent{
						{
							Type: dtos.EventTypeComment,
						},
					},
				},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		assert.Empty(t, diffResult.NewToAllBranches)
		assert.Len(t, diffResult.ExistingOnOtherBranches, 1)

		assert.Len(t, diffResult.ExistingOnOtherBranches[0].EventsToCopy, 2) // combined events from both existing vulns
		assert.Equal(t, "main", *diffResult.ExistingOnOtherBranches[0].EventsToCopy[0].OriginalAssetVersionName)
		assert.Equal(t, "develop", *diffResult.ExistingOnOtherBranches[0].EventsToCopy[1].OriginalAssetVersionName)
	})

	t.Run("should filter out events that were already copied", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type:                     dtos.EventTypeDetected,
							OriginalAssetVersionName: nil, // original event
						},
						{
							Type:                     dtos.EventTypeAccepted,
							OriginalAssetVersionName: utils.Ptr("other-branch"), // already copied event
						},
					},
				},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		assert.Empty(t, diffResult.NewToAllBranches)
		assert.Len(t, diffResult.ExistingOnOtherBranches, 1)

		assert.Len(t, diffResult.ExistingOnOtherBranches[0].EventsToCopy, 1) // only the original event, not the copied one
		assert.Equal(t, dtos.EventTypeDetected, diffResult.ExistingOnOtherBranches[0].EventsToCopy[0].Type)
		assert.Equal(t, "main", *diffResult.ExistingOnOtherBranches[0].EventsToCopy[0].OriginalAssetVersionName)
	})

	t.Run("should handle mixed scenario with new and existing vulnerabilities", func(t *testing.T) {
		foundVulnerabilities := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0001", // new vuln
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: "CVE-2023-0002", // exists on other branch
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
			{
				CVEID: "CVE-2023-0003", // new vuln
				Vulnerability: models.Vulnerability{
					AssetVersionName: "feature-branch",
				},
			},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{
				CVEID: "CVE-2023-0002",
				Vulnerability: models.Vulnerability{
					AssetVersionName: "main",
					Events: []models.VulnEvent{
						{
							Type: dtos.EventTypeDetected,
						},
					},
				},
			},
		}

		diffResult := DiffVulnsBetweenBranches(utils.Map(foundVulnerabilities, utils.Ptr), utils.Map(existingDependencyVulns, utils.Ptr))

		assert.Len(t, diffResult.NewToAllBranches, 2)
		assert.Len(t, diffResult.ExistingOnOtherBranches, 1)

		// check new vulnerabilities
		newCVEs := []string{diffResult.NewToAllBranches[0].CVEID, diffResult.NewToAllBranches[1].CVEID}
		assert.Contains(t, newCVEs, "CVE-2023-0001")
		assert.Contains(t, newCVEs, "CVE-2023-0003")

		// check existing vulnerability
		assert.Equal(t, "CVE-2023-0002", diffResult.ExistingOnOtherBranches[0].CurrentBranchVuln.CVEID)
		assert.Len(t, diffResult.ExistingOnOtherBranches[0].EventsToCopy, 1)
		assert.Equal(t, "main", *diffResult.ExistingOnOtherBranches[0].EventsToCopy[0].OriginalAssetVersionName)
	})
}

// func TestResolveCVERelationsAndReturnFilteredFoundVulns(t *testing.T) {
// 	t.Run("if everything is empty we expect an empty slice", func(t *testing.T) {
// 		filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns([]models.DependencyVuln{}, []models.DependencyVuln{}, map[string][]models.CVERelationShip{})
// 		assert.Len(t, filteredVulns, 0)
// 	})
// 	sortingFunction := func(vuln1 models.DependencyVuln, vuln2 models.DependencyVuln) int {
// 		purlCmp := strings.Compare(*vuln1.ComponentPurl, *vuln2.ComponentPurl)
// 		if purlCmp == 0 {
// 			return strings.Compare(*vuln1.CVEID, *vuln2.CVEID)
// 		}
// 		return purlCmp
// 	}
// 	// start of with 3 vulns: all on different components and with different CVE-IDs
// 	foundVulns := []models.DependencyVuln{
// 		{ComponentPurl: utils.Ptr("pkg:fantasy/stdlib@1.0.0"), CVEID: utils.Ptr("CVE-2042-35567")},
// 		{ComponentPurl: utils.Ptr("pkg:fantasy/math@1.4.2"), CVEID: utils.Ptr("CVE-2042-13367")},
// 		{ComponentPurl: utils.Ptr("pkg:fantasy/json@1.0.0"), CVEID: utils.Ptr("CVE-2042-24267")},
// 	}
// 	existingVulns := []models.DependencyVuln{}
// 	cveRelationships := map[string][]models.CVERelationShip{}
// 	t.Run("test euqual", func(t *testing.T) {
// 		existingVulns = foundVulns
// 		assert.True(t, vulnSlicesEqual(foundVulns, existingVulns))
// 		existingVulns[len(existingVulns)-1].CVEID = utils.Ptr("Keck.w")
// 		assert.False(t, vulnSlicesEqual(foundVulns, existingVulns))
// 		existingVulns = append(existingVulns, models.DependencyVuln{})
// 		assert.False(t, vulnSlicesEqual(foundVulns, existingVulns))
// 	})
// 	t.Run("if we have no existing vulns we want to return the same entries a in foundVulns", func(t *testing.T) {
// 		filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns(foundVulns, existingVulns, cveRelationships)
// 		slices.SortFunc(filteredVulns, sortingFunction)
// 		slices.SortFunc(foundVulns, sortingFunction)
// 		assert.Equal(t, foundVulns, filteredVulns)
// 	})
// 	t.Run("if we have the same state in both slices we want to return the same entries as in foundVulns", func(t *testing.T) {
// 		existingVulns = foundVulns
// 		filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns(foundVulns, existingVulns, cveRelationships)
// 		slices.SortFunc(filteredVulns, sortingFunction)
// 		slices.SortFunc(foundVulns, sortingFunction)
// 		assert.Equal(t, foundVulns, filteredVulns)
// 	})
// 	t.Run("now we have two different CVEs in the same purl, but with no relationship information. This should also return the same entries as in foundVulns", func(t *testing.T) {
// 		foundVulns = append(foundVulns, models.DependencyVuln{ComponentPurl: utils.Ptr("pkg:fantasy/json@1.0.0"), CVEID: utils.Ptr("CVE-2043-24267")})

// 		filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns(foundVulns, existingVulns, cveRelationships)
// 		assert.Len(t, filteredVulns, 4)
// 		slices.SortFunc(filteredVulns, sortingFunction)
// 		slices.SortFunc(foundVulns, sortingFunction)
// 		assert.Equal(t, foundVulns, filteredVulns)
// 	})
// 	t.Run("now we have the same CVE in different purls, but with no relationship information. This should also return the same entries as in foundVulns", func(t *testing.T) {
// 		foundVulns = append(foundVulns, models.DependencyVuln{ComponentPurl: utils.Ptr("pkg:fantasy/math@1.4.2"), CVEID: utils.Ptr("CVE-2042-24267")})
// 		foundVulns = append(foundVulns, models.DependencyVuln{ComponentPurl: utils.Ptr("pkg:fantasy/stdlib@1.0.0"), CVEID: utils.Ptr("CVE-2042-24267")})

// 		filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns(foundVulns, existingVulns, cveRelationships)
// 		assert.Len(t, filteredVulns, 6)
// 		slices.SortFunc(filteredVulns, sortingFunction)
// 		slices.SortFunc(foundVulns, sortingFunction)
// 		assert.Equal(t, foundVulns, filteredVulns)
// 	})
// 	// t.Run("add a new pair of existing and foundVuln but the foundVuln has a different CVE-ID but it relates to the existing CVE-ID", func(t *testing.T) {
// 	// 	existingVulns = append(existingVulns, models.DependencyVuln{ComponentPurl: utils.Ptr("pkg:fantasy/ioutils@1.4.2"), CVEID: utils.Ptr("CVE-2042-24267")})
// 	// 	foundVulns = append(foundVulns, models.DependencyVuln{ComponentPurl: utils.Ptr("pkg:fantasy/ioutils@1.4.2"), CVEID: utils.Ptr("FANTASY-CVE-54322")})
// 	// 	cveRelationships["FANTASY-CVE-54322"] = []models.CVERelationShip{{SourceCVE: "FANTASY-CVE-54322", TargetCVE: "CVE-2042-24267", RelationshipType: dtos.RelationshipTypeAlias}}

// 	// 	filteredVulns := resolveCVERelationsAndReturnFilteredFoundVulns(foundVulns, existingVulns, cveRelationships)
// 	// 	checkResults := foundVulns
// 	// 	checkResults[len(checkResults)-1].CVEID = utils.Ptr("CVE-2042-24267")

// 	// 	assert.Len(t, filteredVulns, 7)
// 	// 	slices.SortFunc(filteredVulns, sortingFunction)
// 	// 	slices.SortFunc(checkResults, sortingFunction)
// 	// 	assert.Equal(t, checkResults, filteredVulns)
// 	// 	assert.Equal(t, foundVulns, filteredVulns)

// 	// })

// }

// // this function checks if 2 vuln slices contain the same elements based on the purl and CVE-ID
// func vulnSlicesEqual(slice1 []models.DependencyVuln, slice2 []models.DependencyVuln) bool {
// 	if len(slice1) != len(slice2) {
// 		return false
// 	}
// 	for _, vuln1 := range slice1 {
// 		foundVulnInOtherSlice := false
// 		for _, vuln2 := range slice2 {
// 			if *vuln1.CVEID == *vuln2.CVEID && *vuln1.ComponentPurl == *vuln2.ComponentPurl {
// 				foundVulnInOtherSlice = true
// 			}
// 		}
// 		if !foundVulnInOtherSlice {
// 			return false
// 		}
// 	}
// 	return true
// }
