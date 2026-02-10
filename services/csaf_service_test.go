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
		assert.Equal(t, 1, distributions[0].totalAmountOfPaths)
		assert.Equal(t, 1, distributions[0].amountUnhandled)

		// TEST remediations
		// we expect 0 remediations if only unhandled vulns are passed
		assert.Len(t, remediations, 0)
	})
	t.Run("multiple different paths inside a vuln which are all handled differently should result in a correct distribution and a correct classification as accepted", func(t *testing.T) {
		eventTime, err := time.Parse(time.RFC3339, "2026-02-11T11:11:11+00:00")
		if err != nil {
			panic(err)
		}
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
		assert.Equal(t, 4, distributions[0].totalAmountOfPaths)

		// all categories should have exactly 1 occurrence
		assert.Equal(t, 1, distributions[0].amountUnhandled)
		assert.Equal(t, 1, distributions[0].amountAccepted)
		assert.Equal(t, 1, distributions[0].amountFixed)
		assert.Equal(t, 1, distributions[0].amountFalsePositive)

		emptyCategories := [][]string{fixed, notAffected, underInvestigation}
		for _, slice := range emptyCategories {
			assert.Len(t, slice, 0)
		}
		assert.Len(t, affected, 1)
		assert.Equal(t, string(productID), affected[0])
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

	cve1.AffectedComponents = append(cve1.AffectedComponents, affectedComponent1, affectedComponent2)

	vuln1Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: fmt.Sprintf("%s@%s", affectedComponent1.PurlWithoutVersion, *affectedComponent1.Version), VulnerabilityPath: []string{}, CVE: cve1}
	vuln1Depth1 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: fmt.Sprintf("%s@%s", affectedComponent1.PurlWithoutVersion, *affectedComponent1.Version), VulnerabilityPath: []string{"dep1"}, CVE: cve1}
	vuln2Depth0 := models.DependencyVuln{Vulnerability: models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID, State: "open", CreatedAt: time2}, ComponentPurl: fmt.Sprintf("%s@%s", affectedComponent3.PurlWithoutVersion, *affectedComponent3.Version), VulnerabilityPath: []string{}, CVE: cve1}

	vuln1Depth0.Artifacts = append(vuln1Depth0.Artifacts, artifact)
	vuln1Depth1.Artifacts = append(vuln1Depth0.Artifacts, artifact)
	vuln2Depth0.Artifacts = append(vuln2Depth0.Artifacts, artifact)

	vuln10Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln1Depth0.CalculateHash(), Model: models.Model{CreatedAt: time2}}
	vuln11Event1 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln1Depth1.CalculateHash(), Model: models.Model{CreatedAt: time2}}
	vuln20Event0 := models.VulnEvent{Type: dtos.EventTypeDetected, VulnID: vuln2Depth0.CalculateHash(), Model: models.Model{CreatedAt: time2}}

	vuln1Depth0.Events = append(vuln1Depth0.Events, vuln10Event1)
	vuln1Depth1.Events = append(vuln1Depth0.Events, vuln11Event1)
	vuln2Depth0.Events = append(vuln2Depth0.Events, vuln20Event0)

	artifact.DependencyVuln = append(artifact.DependencyVuln, vuln1Depth0, vuln1Depth1, vuln2Depth0)
	assetVersion.Artifacts = append(assetVersion.Artifacts, artifact)
	asset.AssetVersions = append(asset.AssetVersions, assetVersion)

	return asset, assetVersion, artifact, []models.DependencyVuln{vuln1Depth0, vuln1Depth1, vuln2Depth0}
}
