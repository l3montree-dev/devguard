// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package integration_tests

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

func CreateOrgProjectAndAssetAssetVersion(db core.DB) (models.Org, models.Project, models.Asset, models.AssetVersion) {
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
