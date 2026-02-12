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
	"fmt"
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

func TestGenerateProductTree(t *testing.T) {
	asset1, assetVersion1, artifact1, vulns := setUpVulns()
	t.Run("test for trivial product tree consisting of 1 asset -> 1 assetVersion -> 1 artifact", func(t *testing.T) {
		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)
		mockAssetVersionRepository.On("GetAllTagsAndDefaultBranchForAsset", mock.Anything, mock.Anything).Return([]models.AssetVersion{assetVersion1}, nil)
		mockArtifactRepository.On("GetByAssetVersions", mock.Anything, mock.Anything).Return([]models.Artifact{artifact1}, nil)

		tree, err := generateProductTree(asset1, mockAssetVersionRepository, mockArtifactRepository, vulns)
		assert.NoError(t, err)

		expectedComponents := []string{vulns[0].ComponentPurl, vulns[2].ComponentPurl}

		allProductIDs := []string{}
		for _, product := range *tree.FullProductNames {
			allProductIDs = append(allProductIDs, string(*product.ProductID))
		}

		allRelationshipIDs := []csaf.ProductID{}
		for _, relationship := range *tree.RelationShips {
			allRelationshipIDs = append(allRelationshipIDs, *relationship.FullProductName.ProductID)
		}
		// amount of components + the artifact itself should appear in the product tree
		assert.Len(t, allProductIDs, len(expectedComponents)+1)
		// each component should have a component_of relationship to the artifact
		assert.Len(t, allRelationshipIDs, len(expectedComponents))

		// check the product ids in detail

		// check if all expected product IDs are present
		for _, expectedID := range append(expectedComponents, normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)) {
			assert.Contains(t, allProductIDs, expectedID)
		}

		// check if all relationships are present and correctly formatted

		for _, component := range expectedComponents {
			// first build the expected id of the relationship
			id := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, artifact1.AssetVersionName, component)
			assert.Contains(t, allRelationshipIDs, id)
		}
	})
	t.Run("expand the product tree with an additional artifact containing a new vuln", func(t *testing.T) {
		artifact2 := artifact1
		artifact2.ArtifactName = "pkg:oci/scanner"

		newVuln := vulns[0]
		newVuln.Artifacts = []models.Artifact{artifact2}
		newVuln.ComponentPurl = "pkg:golang/github.com/sigstore/rekor@v1.3.10"

		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)
		mockArtifactRepository := mocks.NewArtifactRepository(t)

		mockAssetVersionRepository.On("GetAllTagsAndDefaultBranchForAsset", mock.Anything, mock.Anything).Return([]models.AssetVersion{assetVersion1}, nil)
		mockArtifactRepository.On("GetByAssetVersions", mock.Anything, mock.Anything).Return([]models.Artifact{artifact1, artifact2}, nil)

		tree, err := generateProductTree(asset1, mockAssetVersionRepository, mockArtifactRepository, append(vulns, newVuln))
		assert.NoError(t, err)

		expectedComponents := []string{vulns[0].ComponentPurl, vulns[2].ComponentPurl, newVuln.ComponentPurl}

		allProductIDs := []string{}
		for _, product := range *tree.FullProductNames {
			allProductIDs = append(allProductIDs, string(*product.ProductID))
		}

		allRelationshipIDs := []csaf.ProductID{}
		for _, relationship := range *tree.RelationShips {
			allRelationshipIDs = append(allRelationshipIDs, *relationship.FullProductName.ProductID)
		}
		// amount of components + the 2 artifacts itself should appear in the product tree
		assert.Len(t, allProductIDs, len(expectedComponents)+1+1)
		// each component should have a component_of relationship to their respective artifact
		assert.Len(t, allRelationshipIDs, len(expectedComponents))

		// check if all expected product IDs are present
		for _, expectedID := range append(expectedComponents, normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)) {
			assert.Contains(t, allProductIDs, expectedID)
		}

		// check if all relationships are present and correctly formatted
		for _, component := range expectedComponents[:len(expectedComponents)-1] {
			// first build the expected id of the relationship
			id := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, artifact1.AssetVersionName, component)
			assert.Contains(t, allRelationshipIDs, id)
		}
		idNew := artifactNameAndComponentPurlToProductID(artifact2.ArtifactName, artifact2.AssetVersionName, newVuln.ComponentPurl)
		assert.Contains(t, allRelationshipIDs, idNew)
	})
}

func TestCalculateVulnStateInformation(t *testing.T) {
	_, _, artifact1, vulns := setUpVulns()
	eventTime, err := time.Parse(time.RFC3339, "2028-02-11T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	t.Run("generate basic test with 1 dependency vuln for this CVE", func(t *testing.T) {
		testVuln := vulns[0]
		productID := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, testVuln.AssetVersionName, testVuln.ComponentPurl)
		// only pass first vuln
		productStatus, distributions, remediations := calculateVulnStateInformation([]models.DependencyVuln{testVuln})
		affected, notAffected, fixed, underInvestigation := productStatusToSlices(*productStatus)

		// TEST PRODUCT STATUS
		// since the vuln is unhandled these should all be empty
		emptySlices := [][]string{affected, notAffected, fixed}
		for _, slice := range emptySlices {
			assert.Len(t, slice, 0)
		}
		assert.Len(t, underInvestigation, 1)
		assert.Equal(t, string(productID), underInvestigation[0])

		// TEST Distributions
		assert.Len(t, distributions, 1)
		assert.Equal(t, string(productID), distributions[0].productID)
		assert.Equal(t, 1, distributions[0].TotalAmountOfPaths)
		assert.Equal(t, 1, distributions[0].AmountUnhandled)

		// TEST remediations
		// we expect 0 remediations if only unhandled vulns are passed
		assert.Len(t, remediations, 0)
	})
	t.Run("multiple different paths inside a vuln which are all handled differently should result in a correct distribution and a correct classification as accepted", func(t *testing.T) {
		baseVuln := vulns[len(vulns)-1]
		testVulns := []models.DependencyVuln{}

		// build vulns with different paths
		for i := range 4 {
			newVuln := baseVuln
			// append one additional element to the path
			for j := range i {
				newVuln.VulnerabilityPath = append(newVuln.VulnerabilityPath, fmt.Sprintf("Component/v%d.0.0", j+1))
			}
			// also edit the vuln state and append the event
			switch i {
			case 1:
				newVuln.State = dtos.VulnStateFixed
				newVuln.Events = append(newVuln.Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTime}, Type: dtos.EventTypeFixed})
			case 2:
				newVuln.State = dtos.VulnStateAccepted
				newVuln.Events = append(newVuln.Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTime}, Justification: utils.Ptr("This is accepted"), Type: dtos.EventTypeAccepted})
			case 3:
				newVuln.State = dtos.VulnStateFalsePositive
				newVuln.Events = append(newVuln.Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTime}, Justification: utils.Ptr("This is a false positive"), Type: dtos.EventTypeFalsePositive})
			}
			testVulns = append(testVulns, newVuln)
		}

		productID := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, testVulns[0].AssetVersionName, testVulns[0].ComponentPurl)

		productStatus, distributions, remediations := calculateVulnStateInformation(testVulns)
		affected, notAffected, fixed, underInvestigation := productStatusToSlices(*productStatus)

		// since at least 1 path has been marked as accepted the risks is actually present and exploitable
		assert.Len(t, remediations, 1)
		assert.Equal(t, csaf.CSAFRemediationCategoryNoFixPlanned, *remediations[0].Category)
		assert.Equal(t, productID, *(*remediations[0].ProductIds)[0])
		assert.True(t, strings.Contains(*remediations[0].Details, "accepted. Justification: This is accepted"))

		// check if the path distribution have been calculated correctly
		assert.Len(t, distributions, 1)
		assert.Equal(t, 4, distributions[0].TotalAmountOfPaths)
		assert.Equal(t, string(productID), distributions[0].productID)

		// all categories should have exactly 1 occurrence
		assert.Equal(t, 1, distributions[0].AmountUnhandled)
		assert.Equal(t, 1, distributions[0].AmountAccepted)
		assert.Equal(t, 1, distributions[0].AmountFixed)
		assert.Equal(t, 1, distributions[0].AmountFalsePositive)

		emptyCategories := [][]string{fixed, notAffected, underInvestigation}
		for _, slice := range emptyCategories {
			assert.Len(t, slice, 0)
		}
		assert.Len(t, affected, 1)
		assert.Equal(t, string(productID), affected[0])
	})
	t.Run("CVE in multiple different components each with multiple differently handled paths", func(t *testing.T) {
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
			vulnPtr.Events = append(vulnPtr.Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTime}, Justification: utils.Ptr("This is a false positive"), Type: dtos.EventTypeFalsePositive})
		}

		// mark last vuln from artifact 1 as fixed (since its a single path the whole vuln is therefore fixed)
		testVulnsArtifact1[len(testVulnsArtifact1)-1].State = dtos.VulnStateFixed
		testVulnsArtifact1[len(testVulnsArtifact1)-1].Events = append(testVulnsArtifact1[len(testVulnsArtifact1)-1].Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTime}, Type: dtos.EventTypeFixed})

		artifact1ProductID1 := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, artifact1.AssetVersionName, testVulnsArtifact1[0].ComponentPurl)
		artifact1ProductID2 := artifactNameAndComponentPurlToProductID(artifact1.ArtifactName, artifact1.AssetVersionName, testVulnsArtifact1[2].ComponentPurl)

		artifact2ProductID1 := artifactNameAndComponentPurlToProductID(artifact2.ArtifactName, artifact2.AssetVersionName, testVulnsArtifact2[0].ComponentPurl)
		artifact2ProductID2 := artifactNameAndComponentPurlToProductID(artifact2.ArtifactName, artifact2.AssetVersionName, testVulnsArtifact2[2].ComponentPurl)

		productStatus, distributions, remediations := calculateVulnStateInformation(append(testVulnsArtifact1, testVulnsArtifact2...))
		affected, notAffected, fixed, underInvestigation := productStatusToSlices(*productStatus)

		// first test the distributions
		// we expect 1 distribution for each of the 4 products
		assert.Len(t, distributions, 4)

		// reminder: artifact1: end state 3 vulns (comp1: 2 paths (unhandled,unhandled), comp2: 1 path (fixed))
		// reminder: artifact2: end state 4 vulns (comp1: 2 paths (unhandled, falsePositive), comp2: 2 paths (falsePositive, falsePositive))
		for _, distribution := range distributions {
			switch distribution.productID {
			case string(artifact1ProductID1):
				assert.Equal(t, 2, distribution.TotalAmountOfPaths)
				assert.Equal(t, 2, distribution.AmountUnhandled)
				assert.Equal(t, 0, distribution.AmountAccepted, distribution.AmountFixed, distribution.AmountFalsePositive)
			case string(artifact1ProductID2):
				assert.Equal(t, 1, distribution.TotalAmountOfPaths)
				assert.Equal(t, 1, distribution.AmountFixed)
				assert.Equal(t, 0, distribution.AmountAccepted, distribution.AmountUnhandled, distribution.AmountFalsePositive)
			case string(artifact2ProductID1):
				assert.Equal(t, 2, distribution.TotalAmountOfPaths)
				assert.Equal(t, 1, distribution.AmountUnhandled, distribution.AmountFalsePositive)
				assert.Equal(t, 0, distribution.AmountAccepted, distribution.AmountFixed)
			case string(artifact2ProductID2):
				assert.Equal(t, 2, distribution.TotalAmountOfPaths)
				assert.Equal(t, 2, distribution.AmountFalsePositive)
				assert.Equal(t, 0, distribution.AmountAccepted, distribution.AmountUnhandled, distribution.AmountFixed)
			default:
				// unexpected product ID
				t.Fail()
			}
		}

		// now test for correct remediations (we expect 1 for artifact2 comp2 -> false positive)
		assert.Len(t, remediations, 1)
		assert.Equal(t, csaf.CSAFRemediationCategoryMitigation, *remediations[0].Category)
		assert.True(t, strings.Contains(*remediations[0].Details, "marked as false positive. Justification: This is a false positive"))
		assert.Equal(t, string(artifact2ProductID2), string(*(*remediations[0].ProductIds)[0]))

		// finally test the productStatus classifications
		assert.Empty(t, affected)
		assert.Equal(t, 1, len(fixed), len(notAffected))
		assert.Equal(t, string(artifact1ProductID2), fixed[0])
		assert.Equal(t, string(artifact2ProductID2), notAffected[0])

		assert.Len(t, underInvestigation, 2)
	})
}

func TestGetMostRecentJustification(t *testing.T) {
	_, _, _, vulns := setUpVulns()
	eventTimeLatest, err := time.Parse(time.RFC3339, "2026-02-11T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	eventTimeEarlier, err := time.Parse(time.RFC3339, "2026-02-10T11:11:11+00:00")
	if err != nil {
		panic(err)
	}
	t.Run("should return nil if no justification can be found", func(t *testing.T) {
		justification := getMostRecentJustification(vulns)
		assert.Nil(t, justification)
	})
	t.Run("should return the latest justification if multiple are present", func(t *testing.T) {
		vulns[0].State = dtos.VulnStateFalsePositive
		vulns[0].Events = append(vulns[0].Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTimeEarlier}, Type: dtos.EventTypeFalsePositive, Justification: utils.Ptr("this information is outdated")})

		vulns[1].State = dtos.VulnStateFalsePositive
		vulns[1].Events = append(vulns[1].Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTimeLatest}, Type: dtos.EventTypeFalsePositive, Justification: utils.Ptr("this information is up to date")})

		justification := getMostRecentJustification(vulns)
		assert.Equal(t, "this information is up to date", *justification)
	})
}

func TestGenerateTrackingObject(t *testing.T) {
	_, _, artifact1, vulns := setUpVulns()
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
			vulnPtr.Events = append(vulnPtr.Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTimeFalsePositives}, Justification: utils.Ptr("This is a false positive"), Type: dtos.EventTypeFalsePositive})
		}

		// mark last vuln from artifact 1 as fixed (since its a single path the whole vuln is therefore fixed)
		testVulnsArtifact1[len(testVulnsArtifact1)-1].State = dtos.VulnStateFixed
		testVulnsArtifact1[len(testVulnsArtifact1)-1].Events = append(testVulnsArtifact1[len(testVulnsArtifact1)-1].Events, models.VulnEvent{Model: models.Model{CreatedAt: eventTimeFixed}, Type: dtos.EventTypeFixed})

		// calculate all vuln ID so we can sort by it
		for i := range testVulnsArtifact1 {
			testVulnsArtifact1[i].ID = testVulnsArtifact1[i].CalculateHash()
		}
		for i := range testVulnsArtifact2 {
			testVulnsArtifact2[i].ID = testVulnsArtifact2[i].CalculateHash()
		}

		tracking, err := generateTrackingObject(append(testVulnsArtifact1, testVulnsArtifact2...))
		assert.NoError(t, err)

		// the current release date should be the timestamp of the latest event
		currentRelease, err := time.Parse(time.RFC3339, *tracking.CurrentReleaseDate)
		assert.NoError(t, err)
		assert.True(t, eventTimeFixed.Equal(currentRelease))

		// 7 vulns each has a detected event + 1 fix event + 3 false positive events = we expect 11 entries
		assert.Len(t, tracking.RevisionHistory, 11)
		// the version number should match the number of entries
		assert.Equal(t, strconv.Itoa(len(tracking.RevisionHistory)), string(*tracking.Version))

		// all detected Events should happen the earliest
		detectedEntries := tracking.RevisionHistory[:7]
		detectionTime := vulns[0].Events[0].CreatedAt
		for i, entry := range detectedEntries {
			date, err := time.Parse(time.RFC3339, *entry.Date)
			assert.NoError(t, err)
			assert.True(t, detectionTime.Equal(date))

			assert.Equal(t, strconv.Itoa(i+1), string(*entry.Number))
			assert.True(t, strings.Contains(*entry.Summary, "Detected path in package"))
		}

		// then we should find all the false positives events
		falsePositiveEntries := tracking.RevisionHistory[7:10]
		for i, entry := range falsePositiveEntries {
			date, err := time.Parse(time.RFC3339, *entry.Date)
			assert.NoError(t, err)
			assert.True(t, eventTimeFalsePositives.Equal(date))

			assert.Equal(t, strconv.Itoa(i+1+len(detectedEntries)), string(*entry.Number))
			assert.True(t, strings.Contains(*entry.Summary, "Marked path as false positive"))
		}

		// lastly check for the fixed event as the last entry
		entry := tracking.RevisionHistory[len(tracking.RevisionHistory)-1]
		date, err := time.Parse(time.RFC3339, *entry.Date)
		assert.NoError(t, err)
		assert.True(t, eventTimeFixed.Equal(date))

		assert.Equal(t, strconv.Itoa(len(detectedEntries)+len(falsePositiveEntries)+1), string(*entry.Number))
		assert.True(t, strings.Contains(*entry.Summary, "Fixed path in package"))

		amountPurl1 := 0
		amountPurl2 := 0

		amountArtifact1 := 0
		amountArtifact2 := 0

		for _, entry := range tracking.RevisionHistory {
			if strings.Contains(*entry.Summary, "pkg:github.com/jetbrains/kotlin@v872") {
				amountPurl1++
			}
			if strings.Contains(*entry.Summary, "pkg:rpm/redhat/openssh-debugsource@v1.0.1") {
				amountPurl2++
			}
			if strings.Contains(*entry.Summary, normalize.Purlify(artifact1.ArtifactName, artifact1.AssetVersionName)) {
				amountArtifact1++
			}
			if strings.Contains(*entry.Summary, normalize.Purlify(artifact2.ArtifactName, artifact2.AssetVersionName)) {
				amountArtifact2++
			}
		}

		assert.Equal(t, len(tracking.RevisionHistory), amountArtifact1+amountArtifact2, amountPurl1+amountPurl2)
		// 3 detected events 1 fixed event
		assert.Equal(t, 3+1, amountArtifact1)
		// 4 detected events 3 falsePositives
		assert.Equal(t, 4+3, amountArtifact2)
		assert.Equal(t, 5, amountPurl1)
		assert.Equal(t, 6, amountPurl2)

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

func TestConvertAdvisoryToCdxVulnerability(t *testing.T) {
	t.Run("should build the vulnerabilities correctly", func(t *testing.T) {
		// read the advisory in the testdata folder
		advisory, err := csaf.LoadAdvisory("testdata/csaf_report.json")
		assert.Nil(t, err)

		purl, _ := packageurl.FromString("pkg:npm/super-logging@v1.0.0")
		vulns, err := convertAdvisoryToCdxVulnerability(advisory, purl)
		assert.Nil(t, err)

		assert.Equal(t, 1, len(vulns))
		// expect the single vuln to have pkg:npm/debug@3.0.0 as affected package
		assert.Equal(t, "pkg:npm/debug@3.0.0", (*vulns[0].Affects)[0].Ref)
		assert.Equal(t, "Marked as false positive: This doesnt affect us, since we are not using the vulnerable function at all.", vulns[0].Analysis.Detail)
	})
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

	cve1 := models.CVE{CVE: "GO-2026-4309", CreatedAt: time2, Description: "Test Description", CVSS: 7.50, EPSS: utils.Ptr(0.00753)}

	affectedComponent1 := models.AffectedComponent{Ecosystem: "GIT", PurlWithoutVersion: "pkg:github.com/jetbrains/kotlin", Version: utils.Ptr("v872")}
	affectedComponent2 := models.AffectedComponent{Ecosystem: "GIT", PurlWithoutVersion: "pkg:github.com/jetbrains/kotlin", Version: utils.Ptr("build-0.7.536")}
	affectedComponent3 := models.AffectedComponent{Ecosystem: "rpm", PurlWithoutVersion: "pkg:rpm/redhat/openssh-debugsource", Version: utils.Ptr("v1.0.1")}

	cve1.AffectedComponents = append(cve1.AffectedComponents, affectedComponent1, affectedComponent2, affectedComponent3)

	vuln1Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:github.com/jetbrains/kotlin@v872", VulnerabilityPath: []string{}, CVE: cve1}
	vuln1Depth1 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:github.com/jetbrains/kotlin@v872", VulnerabilityPath: []string{"dep1"}, CVE: cve1}
	vuln2Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: "pkg:rpm/redhat/openssh-debugsource@v1.0.1", VulnerabilityPath: []string{}, CVE: cve1}

	vuln1Depth0.Artifacts = append(vuln1Depth0.Artifacts, artifact)
	vuln1Depth1.Artifacts = append(vuln1Depth1.Artifacts, artifact)
	vuln2Depth0.Artifacts = append(vuln2Depth0.Artifacts, artifact)

	vuln10Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln1Depth0.CalculateHash(), Model: models.Model{CreatedAt: time2}}
	vuln11Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln1Depth1.CalculateHash(), Model: models.Model{CreatedAt: time2}}
	vuln20Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln2Depth0.CalculateHash(), Model: models.Model{CreatedAt: time2}}

	vuln1Depth0.Events = append(vuln1Depth0.Events, vuln10Event1)
	vuln1Depth1.Events = append(vuln1Depth1.Events, vuln11Event1)
	vuln2Depth0.Events = append(vuln2Depth0.Events, vuln20Event1)

	artifact.DependencyVuln = append(artifact.DependencyVuln, vuln1Depth0, vuln1Depth1, vuln2Depth0)
	assetVersion.Artifacts = append(assetVersion.Artifacts, artifact)
	asset.AssetVersions = append(asset.AssetVersions, assetVersion)

	return asset, assetVersion, artifact, []models.DependencyVuln{vuln1Depth0, vuln1Depth1, vuln2Depth0}
}
