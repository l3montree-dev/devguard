// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package tests

import (
	"context"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
)

// sbomSeedRoot is the ref a seeded SBOM hangs off. Its children are the
// artifact's direct dependencies, mirroring what the CycloneDX parser produces.
const sbomSeedRoot = "seed-root"

// SeedSBOM stores one SBOM for an artifact the way an ingest would, so tests
// exercise the same content-addressed storage the product reads.
//
// children maps a component id to the component ids it depends on; the entry
// under sbomSeedRoot is the artifact's direct dependencies.
func SeedSBOM(db shared.DB, assetVersion models.AssetVersion, artifactName, source string, children map[string][]string) error {
	tree := normalize.BuildMerkleTree(
		normalize.Adjacency{Children: children},
		sbomSeedRoot,
		artifactName,
	)
	return repositories.NewSBOMRepository(db).SaveTree(context.Background(), nil, models.SBOM{
		AssetID:          assetVersion.AssetID,
		AssetVersionName: assetVersion.Name,
		ArtifactName:     artifactName,
		Source:           source,
	}, tree)
}

// SeedDirectDependencies is SeedSBOM for the common case of an artifact that
// just depends on a flat list of components.
func SeedDirectDependencies(db shared.DB, assetVersion models.AssetVersion, artifactName string, componentIDs ...string) error {
	return SeedSBOM(db, assetVersion, artifactName, "test", map[string][]string{
		sbomSeedRoot: componentIDs,
	})
}

func CreateOrgProjectAndAssetAssetVersion(db shared.DB) (models.Org, models.Project, models.Asset, models.AssetVersion) {
	org := models.Org{
		Name: "Test Org",
		Slug: "test-org",
	}
	err := db.Create(&org).Error
	if err != nil {
		panic(err)
	}
	project := models.Project{
		Name:           "Test Project",
		Slug:           "test-project",
		OrganizationID: org.ID,
	}
	err = db.Create(&project).Error
	if err != nil {
		panic(err)
	}

	asset := models.Asset{
		Name:      "Test Asset",
		ProjectID: project.ID,
		Slug:      "test-asset",
	}

	err = db.Create(&asset).Error
	if err != nil {
		panic(err)
	}
	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       asset.ID,
		DefaultBranch: true,
		Slug:          "main",
		Type:          "branch",
	}
	err = db.Create(&assetVersion).Error
	if err != nil {
		panic(err)
	}

	return org, project, asset, assetVersion
}
