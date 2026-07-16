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

package controllers

import (
	"context"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestIngestVexFromExternalReferences(t *testing.T) {
	asset := models.Asset{}
	assetVersion := models.AssetVersion{Name: "main"}

	t.Run("does nothing when the SBOM has no exploitability-statement references", func(t *testing.T) {
		externalReferenceRepositoryMock := mocks.NewExternalReferenceRepository(t)
		vexRuleServiceMock := mocks.NewVEXRuleService(t)
		scanServiceMock := mocks.NewScanService(t)

		scanController := &ScanController{
			externalReferenceRepository: externalReferenceRepositoryMock,
			vexRuleService:              vexRuleServiceMock,
			ScanService:                 scanServiceMock,
		}

		bom := &cdx.BOM{}

		err := scanController.ingestVexFromExternalReferences(context.Background(), nil, bom, asset, assetVersion)

		assert.NoError(t, err)
		// no external reference should have been stored and no VEX ingestion should be attempted
		externalReferenceRepositoryMock.AssertNotCalled(t, "SaveBatch", mock.Anything, mock.Anything, mock.Anything)
		vexRuleServiceMock.AssertNotCalled(t, "IngestVEXRules", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("fetches and ingests VEX rules when an exploitability-statement reference is present", func(t *testing.T) {
		externalReferenceRepositoryMock := mocks.NewExternalReferenceRepository(t)
		vexRuleServiceMock := mocks.NewVEXRuleService(t)
		scanServiceMock := mocks.NewScanService(t)

		vexURL := "https://example.com/component.vex.json"

		externalReferenceRepositoryMock.EXPECT().SaveBatch(mock.Anything, mock.Anything, mock.MatchedBy(func(refs []models.ExternalReference) bool {
			ref := refs[0]
			return ref.URL == vexURL && ref.AssetID == asset.ID && ref.AssetVersionName == "main"
		})).Return(nil)

		fetchedRules := []models.VEXRule{{}}
		validRefs := []models.ExternalReference{{URL: vexURL, AssetID: asset.ID, AssetVersionName: "main"}}
		scanServiceMock.EXPECT().FetchVexFromUpstream(mock.Anything, asset.ID, "main", mock.MatchedBy(func(urls []string) bool {
			return len(urls) == 1 && urls[0] == vexURL
		})).Return(fetchedRules, validRefs, nil)

		vexRuleServiceMock.EXPECT().IngestVEXRules(mock.Anything, mock.Anything, asset, fetchedRules).Return(nil)

		scanController := &ScanController{
			externalReferenceRepository: externalReferenceRepositoryMock,
			vexRuleService:              vexRuleServiceMock,
			ScanService:                 scanServiceMock,
		}

		refs := []cdx.ExternalReference{
			{Type: cdx.ERTypeExploitabilityStatement, URL: vexURL},
			{Type: cdx.ERTypeOther, URL: "https://example.com/irrelevant"},
		}
		bom := &cdx.BOM{ExternalReferences: &refs}

		err := scanController.ingestVexFromExternalReferences(context.Background(), nil, bom, asset, assetVersion)

		assert.NoError(t, err)
	})
}
